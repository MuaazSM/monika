"""Analyst overrides (PRD §8.1, §12.1; CLAUDE.md rule 6).

POST /_monika/incidents/{id}/override {action, reason, analyst}. All effects apply in the
SAME request (no background task). Every action writes an OVERRIDE audit row — never
updated, never deleted (rule 6) — and emits session.changed over SSE. `reason` is required
and non-empty (422 otherwise).

This route lives in `policy` (not `incidents`): policy sits ABOVE incidents in the layering,
so it may import incidents downward, whereas incidents may not import policy.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator
from redis.asyncio import Redis

from ..incidents.models import (
    IncidentDetailOut,
    IncidentOut,
    IncidentRow,
    OverrideOut,
    OverrideRow,
    SessionStateOut,
    SignalOut,
)
from ..incidents.service import get_incident
from . import denylist
from .ladder import LadderRecord, LadderState, read_ladder, write_ladder

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/_monika", tags=["overrides"])

Action = Literal["acknowledge", "unblock", "false_positive", "force_block"]


class OverrideRequest(BaseModel):
    action: Action
    reason: str
    analyst: str

    @field_validator("reason", "analyst")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty")
        return v


async def _emit_session_changed(request: Request, session_key: str) -> None:
    rec = await read_ladder(request.app.state.redis, session_key)
    request.app.state.broadcaster.publish(
        "session.changed",
        SessionStateOut(
            session_key=session_key,
            state=rec.state.value,
            score=rec.score,
            last_signal_at=rec.last_signal_at or None,
            signals_5m=rec.signals_5m,
        ),
    )


async def _reset_ladder(redis: Redis, session_key: str, state: LadderState, now_ts: float) -> None:
    await write_ladder(
        redis,
        session_key,
        LadderRecord(state=state, score=0, last_signal_at=now_ts, changed_at=now_ts, signals_5m=0),
    )


async def _clear_denylist_for_session(redis: Redis, session_key: str) -> None:
    """Remove this session's revoked jti(s) from denylist:jti (PRD §12.1 unblock)."""
    key = f"revoked_jti:{session_key}"
    jtis = await redis.smembers(key)
    for jti in jtis:
        await denylist.remove(redis, str(jti))
    await redis.delete(key)


@router.post("/incidents/{incident_id}/override", response_model=IncidentDetailOut)
async def override_incident(
    incident_id: UUID, body: OverrideRequest, request: Request
) -> IncidentDetailOut:
    redis = request.app.state.redis
    sf = request.app.state.session_factory
    now = datetime.now(UTC)
    now_ts = now.timestamp()

    parts = await get_incident(sf, incident_id)
    if parts is None:
        raise HTTPException(status_code=404, detail="incident not found")
    incident, _signals, _overrides = parts
    session_key = incident.session_key

    async with sf() as session:
        target = await session.get(IncidentRow, incident_id)
        assert target is not None

        if body.action == "acknowledge":
            target.status = "acknowledged"

        elif body.action in ("unblock", "false_positive"):
            await _reset_ladder(redis, session_key, LadderState.NORMAL, now_ts)
            await _clear_denylist_for_session(redis, session_key)
            target.status = "overridden"
            # false_positive: this session's traffic is benign ground-truth. The precision
            # numerator counts ATTACK-labelled requests, so a benign false positive is
            # already excluded from it by construction (D-06 label-based §10.4).

        elif body.action == "force_block":
            await _reset_ladder(redis, session_key, LadderState.BLOCK, now_ts)
            if target.status != "open":
                # No open incident: raise a fresh analyst-forced one (attribution is the
                # OVERRIDE.analyst row; INCIDENT has no `source` column in §9).
                target = IncidentRow(
                    id=uuid4(),
                    session_key=session_key,
                    endpoint_id=incident.endpoint_id,
                    threat_type=incident.threat_type,
                    risk_score=max(incident.risk_score, 90),
                    confidence=incident.confidence,
                    action_taken="BLOCK",
                    status="open",
                    created_at=now,
                    updated_at=now,
                )
                session.add(target)
                await session.flush()
            else:
                target.action_taken = "BLOCK"

        session.add(
            OverrideRow(
                id=uuid4(),
                incident_id=target.id,
                analyst=body.analyst,
                action=body.action,
                reason=body.reason,
                created_at=now,
            )
        )
        await session.commit()
        result_id = target.id

    await _emit_session_changed(request, session_key)
    logger.info(
        "override.applied", incident_id=str(result_id), action=body.action, analyst=body.analyst
    )

    final = await get_incident(sf, result_id)
    assert final is not None
    inc, signals, overrides = final
    return IncidentDetailOut(
        **IncidentOut.model_validate(inc).model_dump(),
        llm_explanation=inc.llm_explanation,
        llm_next_step=inc.llm_next_step,
        signals=[SignalOut.model_validate(s) for s in signals],
        overrides=[OverrideOut.model_validate(o) for o in overrides],
    )
