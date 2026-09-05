"""Detector D1 — Authorization / BOLA + broken auth + function-level auth (PRD §6.4).

Three rules, all category "auth":
  1. BOLA owner mismatch (sev 70/85/95) — an authenticated request returns an object whose
     owner is not the requester and the requester is not an admin.
  2. Broken authentication (sev 60) — an auth_required endpoint returned 200 with no/invalid
     token.
  3. Function-level auth (sev 70, DECISIONS.md D-10) — an admin_only endpoint accessed by a
     non-admin sub.

The severity-95 escalation counts prior auth signals for the session in the last 5 minutes,
read from Redis key `auth_signals:{session_key}:{minute}` (INT, TTL 300; see CLAUDE.md §7).
D1 increments that counter for every auth signal it emits.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from redis.asyncio import Redis

from . import enum_state
from .base import RequestContext
from .context import derive_session_key
from .signal import Signal

AUTH_WINDOW_MINUTES = 5
AUTH_TTL = 300
ESCALATION_THRESHOLD = 3


def _auth_key(session_key: str, minute: int) -> str:
    return f"auth_signals:{session_key}:{minute}"


def _extract_owners(body: Any, owner_field: str) -> list[Any]:
    """Owner value(s) from a single object or a list of objects."""
    if isinstance(body, dict):
        return [body.get(owner_field)]
    if isinstance(body, list):
        return [item.get(owner_field) for item in body if isinstance(item, dict)]
    return []


def _sensitive_present(body: Any, fields: Iterable[str]) -> bool:
    """True if any configured sensitive field appears as a key in the response object(s)."""
    fields = tuple(fields)
    if not fields:
        return False
    objs = body if isinstance(body, list) else [body] if isinstance(body, dict) else []
    return any(isinstance(o, dict) and any(f in o for f in fields) for o in objs)


class AuthDetector:
    """D1. Constructor takes the admin allow-list (top-level `admin_subs` from the config)."""

    name = "d1_auth"

    def __init__(self, admin_subs: Iterable[int]) -> None:
        self.admin_subs = set(admin_subs)

    async def _prior_auth_count(self, redis: Redis, session_key: str, minute: int) -> int:
        keys = [_auth_key(session_key, minute - i) for i in range(AUTH_WINDOW_MINUTES)]
        vals = await redis.mget(keys)
        return sum(int(v) for v in vals if v is not None)

    async def _bump_auth_count(self, redis: Redis, session_key: str, minute: int, by: int) -> None:
        key = _auth_key(session_key, minute)
        await redis.incrby(key, by)
        await redis.expire(key, AUTH_TTL)

    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]:
        ep = ctx.endpoint
        if ep is None or not ep.auth_required:
            return []

        status = ctx.response.status
        session_key = derive_session_key(ctx.jwt, ctx.ip)
        minute = int(ctx.started_at.timestamp() // 60)
        prior = await self._prior_auth_count(redis, session_key, minute)

        signals: list[Signal] = []
        sub = ctx.jwt.sub if ctx.jwt is not None else None

        # Rule 2: broken authentication — auth_required endpoint served 200 with no/invalid token.
        if ctx.jwt is None and status == 200:
            signals.append(
                Signal(
                    category="auth",
                    severity=60,
                    evidence={
                        "endpoint": f"{ep.method} {ep.path_pattern}",
                        "status": status,
                        "reason": "no_or_invalid_token",
                    },
                    request_id=ctx.request_id,
                    endpoint_id=ep.endpoint_id,
                    session_key=session_key,
                )
            )

        # Rule 3: function-level auth — non-admin sub on an admin_only endpoint (D-10).
        if ep.admin_only and sub is not None and sub not in self.admin_subs and status == 200:
            signals.append(
                Signal(
                    category="auth",
                    severity=70,
                    evidence={
                        "jwt_sub": sub,
                        "endpoint": f"{ep.method} {ep.path_pattern}",
                        "admin_only": True,
                    },
                    request_id=ctx.request_id,
                    endpoint_id=ep.endpoint_id,
                    session_key=session_key,
                )
            )

        # Rule 1: BOLA owner mismatch.
        if sub is not None and ep.owner_field and status == 200 and sub not in self.admin_subs:
            owners = _extract_owners(ctx.response.body_json, ep.owner_field)
            # Share the extracted owner values with D2 (distinct-owner enumeration) via
            # Redis — D2 reads these; it never imports d1_auth.
            await enum_state.record_owners(
                redis,
                session_key,
                ep.endpoint_id,
                [o for o in owners if o is not None],
                ctx.started_at.timestamp(),
            )
            foreign = [o for o in owners if o is not None and str(o) != str(sub)]
            if foreign:
                sensitive_present = _sensitive_present(ctx.response.body_json, ep.sensitive_fields)
                severity = 70
                if sensitive_present:
                    severity = 85
                if prior >= ESCALATION_THRESHOLD:
                    severity = 95
                requested_object = ctx.path_params.get(ep.id_param) if ep.id_param else None
                object_owner = foreign[0] if len(foreign) == 1 else foreign
                signals.append(
                    Signal(
                        category="auth",
                        severity=severity,
                        evidence={
                            "jwt_sub": sub,
                            "requested_object": requested_object,
                            "object_owner": object_owner,
                            "sensitive_fields_present": sensitive_present,
                            "prior_auth_signals_5m": prior,
                        },
                        request_id=ctx.request_id,
                        endpoint_id=ep.endpoint_id,
                        session_key=session_key,
                    )
                )

        if signals:
            await self._bump_auth_count(redis, session_key, minute, len(signals))
        return signals
