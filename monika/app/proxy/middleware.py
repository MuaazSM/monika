"""The proxy request handler, mounted on any /api/{path:path}.

Pipeline (PRD §5.2, Figure 2; CLAUDE.md rule 4 — enforcement is one request behind detection):
  1. build request identity + JWT claims + session_key
  2. PRE-FORWARD enforcement (enforce.pre_forward): jti denylist, then ladder state. May
     short-circuit (401/403/429) without ever calling upstream.
  3. forward upstream, measure latency
  4. assemble the RequestContext (request + response)
  5. persist one REQUEST_LOG row with the enforcement action actually applied
  6. detection on the pair -> score -> apply the ladder (post-forward; D1/D4 need the body)
  7. return the upstream response to the client
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Request, Response
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..detection.baselines import bump_rate_counters, record_request
from ..detection.context import (
    JWTClaims,
    RequestContext,
    ResponseContext,
    derive_session_key,
)
from ..detection.engine import run_detectors
from ..endpoints.service import mirror_baseline_to_db
from ..incidents.models import IncidentOut, RequestLog, SessionStateOut
from ..incidents.service import record_incident
from ..policy.ladder import apply_signals, read_ladder
from ..scoring.confidence import confidence
from ..scoring.score import score
from ..scoring.state import SessionState
from ..settings import Settings
from . import enforce
from .forward import ForwardResult, forward_request
from .jwt import decode_bearer

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["proxy"])

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def _client_ip(request: Request) -> str:
    """Prefer X-Forwarded-For's first hop, else the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _maybe_json(body: bytes) -> Any:
    """Parse JSON, or None if the body is empty or not JSON."""
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


async def _log_row(
    session_factory: async_sessionmaker[Any],
    *,
    request_id: str,
    session_key: str,
    method: str,
    path: str,
    status_code: int,
    resp_bytes: int,
    latency_ms: float,
    action_applied: str,
    label: str | None,
) -> None:
    """Persist exactly one REQUEST_LOG row (action_applied drives the precision panel)."""
    async with session_factory() as session:
        session.add(
            RequestLog(
                request_id=request_id,
                session_key=session_key,
                method=method,
                path=path,
                status_code=status_code,
                resp_bytes=resp_bytes,
                latency_ms=round(latency_ms),
                action_applied=action_applied,
                label=label,
            )
        )
        await session.commit()


# include_in_schema=False: a multi-method api_route on one function makes FastAPI emit the
# same operationId for every method (a real duplicate-operation-ID schema bug), and this
# catch-all forwards arbitrary traffic anyway — no typed client should call it directly.
@router.api_route("/api/{path:path}", methods=_METHODS, include_in_schema=False)
async def proxy(request: Request, path: str) -> Response:
    """Forward /api/* to the upstream demo API, enforcing the ladder around it."""
    settings: Settings = request.app.state.settings
    redis = request.app.state.redis
    session_factory = request.app.state.session_factory
    request_id = str(uuid.uuid4())
    started_at = datetime.now(UTC)
    now_ts = started_at.timestamp()

    body = await request.body()
    jwt_claims: JWTClaims | None = decode_bearer(
        request.headers.get("authorization"), settings.jwt_secret
    )
    ip = _client_ip(request)
    session_key = derive_session_key(jwt_claims, ip)
    label = request.headers.get("x-monika-label")

    endpoint, path_params = request.app.state.endpoints.match(request.method, request.url.path)
    log = logger.bind(request_id=request_id, session_key=session_key)

    # --- step 2: pre-forward enforcement ---
    pre = await enforce.pre_forward(
        redis,
        settings,
        session_key=session_key,
        jwt_claims=jwt_claims,
        step_up_header=request.headers.get("x-step-up"),
        now_ts=now_ts,
        session_factory=session_factory,
    )
    if pre.short_circuit is not None:
        resp = pre.short_circuit
        await _log_row(
            session_factory,
            request_id=request_id,
            session_key=session_key,
            method=request.method,
            path=request.url.path,
            status_code=resp.status_code,
            resp_bytes=len(resp.body),
            latency_ms=(datetime.now(UTC) - started_at).total_seconds() * 1000.0,
            action_applied=pre.action,
            label=label,
        )
        log.info(
            "proxy.enforced",
            method=request.method,
            path=request.url.path,
            status=resp.status_code,
            action=pre.action,
        )
        return resp

    # --- step 3: forward ---
    result: ForwardResult = await forward_request(
        request.app.state.http_client,
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        headers=dict(request.headers),
        body=body,
    )

    # --- step 4: assemble the request+response context ---
    ctx = RequestContext(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        path_params=path_params,
        query=dict(request.query_params),
        headers=dict(request.headers),
        body_json=_maybe_json(body),
        jwt=jwt_claims,
        ip=ip,
        endpoint=endpoint,
        response=ResponseContext(
            status=result.status,
            bytes=len(result.body),
            body_json=_maybe_json(result.body),
        ),
        started_at=started_at,
        latency_ms=result.latency_ms,
        label=label,
    )

    # --- step 5: persist REQUEST_LOG (forwarded requests applied "allow" enforcement) ---
    await _log_row(
        session_factory,
        request_id=request_id,
        session_key=session_key,
        method=ctx.method,
        path=ctx.path,
        status_code=ctx.response.status,
        resp_bytes=ctx.response.bytes,
        latency_ms=ctx.latency_ms,
        action_applied=pre.action,
        label=label,
    )

    # --- baselines + rate counters (only for configured endpoints) ---
    if endpoint is not None:
        await bump_rate_counters(redis, session_key, endpoint.endpoint_id, now_ts)
        snapshot = await record_request(redis, endpoint.endpoint_id, ctx.response.bytes, now_ts)
        await mirror_baseline_to_db(
            session_factory,
            endpoint.endpoint_id,
            snapshot.rpm_mean,
            snapshot.rpm_std,
            snapshot.bytes_mean,
        )

    # --- step 6: detection -> score -> ladder (post-forward; the escalation hits the NEXT
    #     request, keeping enforcement one step behind detection) ---
    signals = await run_detectors(request.app.state.detectors, ctx, redis)
    if signals:
        prior = await read_ladder(redis, session_key)
        session_state = SessionState(
            signals_last_5m=prior.signals_5m,
            current_state=prior.state.value,
            current_score=prior.score,
        )
        request_score = score(signals, session_state)
        request_confidence = confidence(signals, session_state)
        new_state = await apply_signals(
            redis,
            session_key,
            score=request_score,
            categories={s.category for s in signals},
            now_ts=now_ts,
            divisor=settings.ladder_time_divisor,
            jti=jwt_claims.jti if jwt_claims else None,
            challenge_passed=pre.challenge_passed,
            session_factory=session_factory,
        )
        # Create/update the incident (dedup by session+threat+window). Needs a configured
        # endpoint (INCIDENT.endpoint_id is a non-null FK); apply_signals wrote the SESSION
        # row first, satisfying the session_key FK. Sub-SAFE scores create nothing.
        broadcaster = request.app.state.broadcaster
        if endpoint is not None:
            incident_result = await record_incident(
                session_factory,
                session_key=session_key,
                endpoint_id=endpoint.endpoint_id,
                signals=signals,
                score=request_score,
                confidence=request_confidence,
                action_taken=new_state.value,
                now=started_at,
                explainer_queue=request.app.state.explainer_queue,
                endpoint_label=f"{endpoint.method} {endpoint.path_pattern}",
            )
            if incident_result is not None:
                incident, created = incident_result
                broadcaster.publish(
                    "incident.created" if created else "incident.updated",
                    IncidentOut.model_validate(incident),
                )
        # session.changed carries the SessionStateOut shape (matches GET /_monika/sessions).
        after = await read_ladder(redis, session_key)
        broadcaster.publish(
            "session.changed",
            SessionStateOut(
                session_key=session_key,
                state=after.state.value,
                score=after.score,
                last_signal_at=after.last_signal_at or None,
                signals_5m=after.signals_5m,
            ),
        )
        log.info(
            "proxy.scored",
            score=request_score,
            confidence=request_confidence,
            categories=sorted({s.category for s in signals}),
            new_state=new_state.value,
        )

    log.info(
        "proxy.forwarded",
        method=ctx.method,
        path=ctx.path,
        status=ctx.response.status,
        latency_ms=ctx.latency_ms,
        action=pre.action,
    )

    # --- step 7: relay upstream response ---
    return Response(content=result.body, status_code=result.status, headers=result.headers)
