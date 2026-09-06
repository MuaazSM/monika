"""Demo-data reset (dashboard Settings "Reset demo data" button; CLAUDE.md rule 6).

Clears incident/signal/session/request_log/attack_plan state so a rehearsal can start
clean, WITHOUT touching `baseline:*` (a fresh learning phase is a separate, minutes-long
operation — `make reset` — not something a button click should block on) and WITHOUT ever
deleting an OVERRIDE row or an incident an override still references (rule 6: overrides
are a permanent audit trail). Any incident an analyst has already acted on survives a
reset intact, along with its signals and overrides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..incidents.models import (
    AttackPlanRow,
    IncidentRow,
    OverrideRow,
    RequestLog,
    SessionRow,
    SignalRow,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/_monika", tags=["reset"])

# Transient per-session/detector state (mirrors tests/integration/test_scenarios.py::_reset).
# baseline:* is deliberately excluded — baselines are expensive to relearn and unrelated to
# incident/session housekeeping.
_REDIS_PATTERNS = (
    "ladder:*",
    "blocked_attempts:*",
    "enum:*",
    "enum_owner:*",
    "auth_signals:*",
    "rate:*",
    "login_fail:*",
    "login_users:*",
    "revoked_jti:*",
    "exposure_pages:*",
    "denylist:jti",
)


@dataclass(frozen=True)
class ResetResult:
    incidents_cleared: int
    signals_cleared: int
    preserved_incidents: int  # kept because an override still references them (rule 6)


async def reset_demo_data(
    session_factory: async_sessionmaker[AsyncSession], redis: Redis
) -> ResetResult:
    async with session_factory() as session:
        overridden_ids = select(OverrideRow.incident_id)
        preserved_count = len(
            (
                await session.execute(
                    select(IncidentRow.id).where(IncidentRow.id.in_(overridden_ids))
                )
            )
            .scalars()
            .all()
        )

        signals_result = cast(
            "CursorResult[Any]",
            await session.execute(
                delete(SignalRow).where(SignalRow.incident_id.not_in(overridden_ids))
            ),
        )
        incidents_result = cast(
            "CursorResult[Any]",
            await session.execute(delete(IncidentRow).where(IncidentRow.id.not_in(overridden_ids))),
        )
        # A preserved (overridden) incident carries a FK to its session row (incident_
        # session_key_fkey), so deleting every session unconditionally throws a
        # ForeignKeyViolationError as soon as any override exists — exclude the sessions a
        # preserved incident still references, same as the incidents/signals exclusion above.
        preserved_session_keys = select(IncidentRow.session_key).where(
            IncidentRow.id.in_(overridden_ids)
        )
        await session.execute(delete(RequestLog))
        await session.execute(
            delete(SessionRow).where(SessionRow.session_key.not_in(preserved_session_keys))
        )
        await session.execute(delete(AttackPlanRow))
        await session.commit()

    for pattern in _REDIS_PATTERNS:
        keys = [key async for key in redis.scan_iter(match=pattern, count=500)]
        if keys:
            await redis.delete(*keys)

    return ResetResult(
        incidents_cleared=incidents_result.rowcount or 0,
        signals_cleared=signals_result.rowcount or 0,
        preserved_incidents=preserved_count,
    )


class ResetOut(BaseModel):
    incidents_cleared: int
    signals_cleared: int
    preserved_incidents: int


@router.post("/reset", response_model=ResetOut)
async def reset(request: Request) -> ResetOut:
    """Dashboard Settings "Reset demo data". Fast (<1s): clears incidents/sessions/transient
    detector state but keeps learned baselines — for a full re-seed use `make reset` (CLI)."""
    result = await reset_demo_data(request.app.state.session_factory, request.app.state.redis)
    logger.info(
        "reset.demo_data",
        incidents_cleared=result.incidents_cleared,
        signals_cleared=result.signals_cleared,
        preserved_incidents=result.preserved_incidents,
    )
    return ResetOut(
        incidents_cleared=result.incidents_cleared,
        signals_cleared=result.signals_cleared,
        preserved_incidents=result.preserved_incidents,
    )
