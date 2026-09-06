"""Demo-data reset (CLAUDE.md rule 6: overrides — and the incidents they reference — must
never be deleted)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.incidents.models import (
    EndpointConfigRow,
    IncidentRow,
    OverrideRow,
    RequestLog,
    SessionRow,
    SignalRow,
)
from app.policy.reset import router as reset_router

EID = uuid4()


@pytest.fixture
async def sf():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)

    # SQLite ignores FK constraints unless told otherwise — turn enforcement on so a
    # regression here (e.g. deleting a session a preserved incident still references) fails
    # the test the same way Postgres rejects it in production, instead of silently passing.
    @event.listens_for(engine.sync_engine, "connect")
    def _enable_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _incident(session_key: str, status: str = "open") -> IncidentRow:
    now = datetime.now(UTC)
    return IncidentRow(
        id=uuid4(),
        session_key=session_key,
        endpoint_id=EID,
        threat_type="BOLA_ENUMERATION",
        risk_score=90,
        confidence=80,
        action_taken="BLOCK",
        status=status,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
async def app(sf):
    application = FastAPI()
    application.state.session_factory = sf
    application.state.redis = aioredis.FakeRedis(decode_responses=True)
    application.include_router(reset_router)
    yield application
    await application.state.redis.aclose()


async def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://monika")


async def test_reset_clears_incidents_without_overrides(app, sf) -> None:
    async with sf() as s:
        s.add(EndpointConfigRow(id=EID, method="GET", path_pattern="/api/x", auth_required=False))
        s.add(SessionRow(session_key="1", ladder_state="BLOCK", current_score=90))
        await s.flush()  # session/endpoint rows must exist before an incident FKs to them
        plain = _incident("1")
        s.add(plain)
        s.add(
            RequestLog(
                request_id="r1",
                session_key="1",
                method="GET",
                path="/api/x",
                status_code=200,
                resp_bytes=10,
                latency_ms=5,
            )
        )
        await s.commit()

    async with await _client(app) as c:
        resp = await c.post("/_monika/reset")
    assert resp.status_code == 200
    body = resp.json()
    assert body["incidents_cleared"] == 1
    assert body["preserved_incidents"] == 0

    async with sf() as s:
        assert (await s.execute(select(IncidentRow))).scalars().all() == []
        assert (await s.execute(select(SessionRow))).scalars().all() == []
        assert (await s.execute(select(RequestLog))).scalars().all() == []


async def test_reset_never_deletes_overridden_incidents_or_overrides(app, sf) -> None:
    """Rule 6: an incident with an override — and the override itself — survive a reset.

    Also a regression test for a real bug: SessionRow was deleted unconditionally, but
    IncidentRow.session_key has a FK to it, so this crashed with a ForeignKeyViolationError
    on Postgres as soon as any override existed and its session row was still present —
    SQLite's default FK-checks-off behavior let the original test pass despite the bug.
    """
    async with sf() as s:
        s.add(EndpointConfigRow(id=EID, method="GET", path_pattern="/api/x", auth_required=False))
        # The preserved incident's own session must survive too (FK) ...
        s.add(SessionRow(session_key="2", ladder_state="BLOCK", current_score=90))
        # ... while an unrelated session with no surviving incident must still be cleared.
        s.add(SessionRow(session_key="3", ladder_state="NORMAL", current_score=0))
        await s.flush()  # session/endpoint rows must exist before an incident FKs to them
        overridden = _incident("2", status="overridden")
        s.add(overridden)
        s.add(
            SignalRow(
                id=uuid4(),
                incident_id=overridden.id,
                category="auth",
                severity=70,
                evidence={},
                request_id="r2",
                session_key="2",
                endpoint_id=EID,
            )
        )
        s.add(
            OverrideRow(
                id=uuid4(),
                incident_id=overridden.id,
                analyst="alice",
                action="false_positive",
                reason="known-good load test",
            )
        )
        await s.commit()
        overridden_id = overridden.id

    async with await _client(app) as c:
        resp = await c.post("/_monika/reset")
    assert resp.status_code == 200
    body = resp.json()
    assert body["incidents_cleared"] == 0
    assert body["preserved_incidents"] == 1

    async with sf() as s:
        remaining = (await s.execute(select(IncidentRow))).scalars().all()
        assert [i.id for i in remaining] == [overridden_id]
        assert len((await s.execute(select(OverrideRow))).scalars().all()) == 1
        assert len((await s.execute(select(SignalRow))).scalars().all()) == 1
        remaining_sessions = {
            r.session_key for r in (await s.execute(select(SessionRow))).scalars().all()
        }
        assert remaining_sessions == {"2"}  # preserved incident's session kept, "3" cleared


async def test_reset_clears_transient_redis_but_keeps_baselines(app) -> None:
    redis = app.state.redis
    await redis.hset("ladder:1", mapping={"state": "BLOCK", "score": 90})
    await redis.sadd("denylist:jti", "dead-jti")
    await redis.hset("baseline:some-endpoint:rpm", mapping={"mean": 10.0, "std": 1.0, "n": 100})

    async with await _client(app) as c:
        resp = await c.post("/_monika/reset")
    assert resp.status_code == 200

    assert await redis.exists("ladder:1") == 0
    assert await redis.exists("denylist:jti") == 0
    assert await redis.exists("baseline:some-endpoint:rpm") == 1
