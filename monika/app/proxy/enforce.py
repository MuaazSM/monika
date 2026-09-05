"""Pre-forward enforcement (PRD §5.2, Figure 2; CLAUDE.md rule 4).

The order here is non-negotiable. Detection is NEVER run here — D1 and D4 need the response
body, so detection is strictly post-forward (rule 4). This module only reads existing state
(the jti denylist and the Redis ladder) and decides whether to short-circuit the request.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt as _jwt
from fastapi import Response
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..detection.base import JWTClaims
from ..policy import denylist
from ..policy.ladder import LadderState, apply_decay, read_ladder, revoke_session
from ..settings import Settings

RATE_LIMIT_RPM = 10
# DECISIONS.md D-14: a BLOCKed session that keeps attacking with its token is revoked after
# this many blocked attempts — the "auth/exposure activity while BLOCKED" REVOKE trigger
# (§8.1), which detection can't reach because blocked requests are 403'd pre-forward.
BLOCKED_REVOKE_THRESHOLD = 3


@dataclass(slots=True)
class PreForwardResult:
    """Outcome of the pre-forward checks."""

    short_circuit: Response | None  # non-None => return this without forwarding
    action: str  # allow | rate_limit | challenge | block | revoke
    challenge_passed: bool = False


def _body(detail: str, incident_id: str | None) -> dict[str, object]:
    body: dict[str, object] = {"detail": detail}
    if incident_id is not None:
        body["incident_id"] = incident_id
    return body


def _valid_step_up(header: str | None, secret: str) -> bool:
    """A valid X-Step-Up is a fresh (unexpired), correctly-signed token from /api/step-up."""
    if not header:
        return False
    token = header.split(" ", 1)[1].strip() if header.lower().startswith("bearer ") else header
    try:
        _jwt.decode(token, secret, algorithms=["HS256"], options={"verify_sub": False})
    except Exception:
        return False
    return True


async def pre_forward(
    redis: Redis,
    settings: Settings,
    *,
    session_key: str,
    jwt_claims: JWTClaims | None,
    step_up_header: str | None,
    now_ts: float,
    incident_id: str | None = None,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> PreForwardResult:
    """Run the pre-forward checks in the mandated order and return the decision."""
    divisor = settings.ladder_time_divisor

    # 1. jti denylist — the ONLY pre-forward hard check (REVOKE).
    if jwt_claims is not None and await denylist.contains(redis, jwt_claims.jti):
        return PreForwardResult(
            JSONResponse(status_code=401, content=_body("token revoked", incident_id)),
            action="revoke",
        )

    # 2. ladder state (decay first so a quiet session is enforced at its real, lower rung).
    await apply_decay(redis, session_key, now_ts=now_ts, divisor=divisor)
    rec = await read_ladder(redis, session_key)
    state = rec.state

    if state == LadderState.BLOCK:
        # D-14: a persistent BLOCKed attacker still wielding its token gets revoked.
        if jwt_claims is not None:
            attempts = await redis.incr(f"blocked_attempts:{session_key}")
            await redis.expire(f"blocked_attempts:{session_key}", 300)
            if attempts >= BLOCKED_REVOKE_THRESHOLD:
                await revoke_session(
                    redis,
                    session_key,
                    jti=jwt_claims.jti,
                    now_ts=now_ts,
                    score=rec.score,
                    session_factory=session_factory,
                )
                return PreForwardResult(
                    JSONResponse(status_code=401, content=_body("token revoked", incident_id)),
                    action="revoke",
                )
        return PreForwardResult(
            JSONResponse(status_code=403, content=_body("blocked", incident_id)),
            action="block",
        )

    if state == LadderState.RATE_LIMIT:
        minute = int(now_ts // 60)
        count = int(await redis.get(f"rate:{session_key}:{minute}") or 0)
        if count >= RATE_LIMIT_RPM:
            retry_after = 60 - int(now_ts) % 60
            return PreForwardResult(
                JSONResponse(
                    status_code=429,
                    content=_body("rate limited", incident_id),
                    headers={"Retry-After": str(retry_after)},
                ),
                action="rate_limit",
            )

    if state == LadderState.CHALLENGE:
        if _valid_step_up(step_up_header, settings.jwt_secret):
            # 3. passed challenge — forward and arm the after-passed-challenge escalation.
            return PreForwardResult(None, action="allow", challenge_passed=True)
        return PreForwardResult(
            JSONResponse(
                status_code=401,
                content=_body("step-up required", incident_id),
                headers={"WWW-Authenticate": "StepUp"},
            ),
            action="challenge",
        )

    # NORMAL / OBSERVE (and RATE_LIMIT under the cap) → forward.
    return PreForwardResult(None, action="allow")
