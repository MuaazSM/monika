"""Stats/precision panel (PRD §10.4, D-06). Empty window returns nulls, not zeros."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import IncidentRow, RequestLog
from app.stats.service import compute_stats

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
async def sf():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _rl(action, label, *, minutes_ago=1, sk="s"):
    return RequestLog(
        request_id=str(uuid4()),
        session_key=sk,
        method="GET",
        path="/api/x",
        status_code=200,
        resp_bytes=10,
        latency_ms=1,
        action_applied=action,
        label=label,
        created_at=NOW - timedelta(minutes=minutes_ago),
    )


async def test_empty_window_returns_nulls_not_zeros(sf) -> None:
    stats = await compute_stats(sf, now=NOW)
    assert stats.precision is None  # not 0.0
    assert stats.recall is None  # not 0.0
    assert stats.total_requests == 0
    assert stats.benign_by_rung == {}


async def test_precision_ratio(sf) -> None:
    async with sf() as s:
        # 3 enforced attack requests + 1 enforced benign (false positive) = 4 enforced total
        s.add(_rl("block", "attack:idor"))
        s.add(_rl("rate_limit", "attack:idor"))
        s.add(_rl("challenge", "attack:idor"))
        s.add(_rl("rate_limit", "benign"))  # benign that reached RATE_LIMIT -> lowers precision
        s.add(_rl("allow", "benign"))  # not enforced -> excluded from precision
        await s.commit()
    stats = await compute_stats(sf, now=NOW)
    assert stats.precision == 0.75  # 3 attack / 4 enforced
    assert stats.benign_by_rung == {"rate_limit": 1, "allow": 1}


async def test_recall_ratio(sf) -> None:
    async with sf() as s:
        # two scenarios run; only idor produced an incident >= 60 for its session
        s.add(_rl("block", "attack:idor", sk="742"))
        s.add(_rl("rate_limit", "attack:scrape", sk="900"))
        s.add(
            IncidentRow(
                id=uuid4(),
                session_key="742",
                endpoint_id=uuid4(),
                threat_type="BOLA_ENUMERATION",
                risk_score=95,
                confidence=70,
                action_taken="BLOCK",
                status="open",
                created_at=NOW - timedelta(minutes=1),
                updated_at=NOW - timedelta(minutes=1),
            )
        )
        await s.commit()
    stats = await compute_stats(sf, now=NOW)
    assert stats.recall == 0.5  # 1 detected (idor) / 2 run (idor, scrape)


async def test_window_excludes_old_rows(sf) -> None:
    async with sf() as s:
        s.add(_rl("block", "attack:idor", minutes_ago=45))  # outside 30-min window
        await s.commit()
    stats = await compute_stats(sf, now=NOW)
    assert stats.precision is None  # the only enforced row is out of window
    assert stats.total_requests == 1  # tiles are all-time


async def test_false_positive_override_excluded_from_numerator(sf) -> None:
    from uuid import uuid4

    from app.incidents.models import OverrideRow

    async with sf() as s:
        # one attack-labelled enforced request from a session later marked false_positive
        s.add(_rl("block", "attack:idor", sk="742"))
        inc = IncidentRow(
            id=uuid4(),
            session_key="742",
            endpoint_id=uuid4(),
            threat_type="BOLA_ENUMERATION",
            risk_score=95,
            confidence=70,
            action_taken="BLOCK",
            status="overridden",
            created_at=NOW - timedelta(minutes=1),
            updated_at=NOW - timedelta(minutes=1),
        )
        s.add(inc)
        await s.flush()
        s.add(
            OverrideRow(
                id=uuid4(),
                incident_id=inc.id,
                analyst="a",
                action="false_positive",
                reason="benign on review",
                created_at=NOW - timedelta(minutes=1),
            )
        )
        await s.commit()
    stats = await compute_stats(sf, now=NOW)
    # the enforced request is in the denominator but excluded from the numerator -> 0/1
    assert stats.precision == 0.0
