"""Override API tests (PRD §8.1, §12.1; CLAUDE.md rule 6)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.detection.context import JWTClaims
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import EndpointConfigRow, IncidentRow, OverrideRow, SessionRow
from app.incidents.sse import Broadcaster
from app.policy import denylist
from app.policy.ladder import ladder_key, read_ladder
from app.policy.overrides import router as overrides_router
from app.proxy import enforce
from app.settings import Settings

EID = uuid4()
SK = "742"
SECRET = "test-secret"


@pytest.fixture
async def sf():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _seed_incident(sf, status="open") -> IncidentRow:
    async with sf() as s:
        s.add(
            EndpointConfigRow(
                id=EID,
                method="GET",
                path_pattern="/api/users/{id}",
                sensitive_fields=[],
                auth_required=True,
                admin_only=False,
            )
        )
        s.add(SessionRow(session_key=SK, ladder_state="REVOKE", current_score=100))
        inc = IncidentRow(
            id=uuid4(),
            session_key=SK,
            endpoint_id=EID,
            threat_type="BOLA_ENUMERATION",
            risk_score=100,
            confidence=90,
            action_taken="REVOKE",
            status=status,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        s.add(inc)
        await s.commit()
        await s.refresh(inc)
        return inc


@pytest.fixture
async def app(sf):
    application = FastAPI()
    application.state.session_factory = sf
    application.state.redis = aioredis.FakeRedis(decode_responses=True)
    application.state.broadcaster = Broadcaster()
    application.include_router(overrides_router)
    yield application
    await application.state.redis.aclose()


async def _client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://monika"
    ) as c:
        yield c


async def _override(client, incident_id, action, reason="analyst confirmed", analyst="alice"):
    return await client.post(
        f"/_monika/incidents/{incident_id}/override",
        json={"action": action, "reason": reason, "analyst": analyst},
    )


async def test_unblock_on_revoked_clears_denylist_and_sets_normal(app, sf) -> None:
    # §12.1: unblock on a REVOKED session clears the denylist entry AND sets NORMAL.
    inc = await _seed_incident(sf)
    redis = app.state.redis
    await denylist.add(redis, "dead-jti")
    await redis.sadd(f"revoked_jti:{SK}", "dead-jti")
    await redis.hset(
        ladder_key(SK),
        mapping={
            "state": "OBSERVE",
            "score": 0,
            "last_signal_at": 1.0,
            "changed_at": 1.0,
            "signals_5m": 0,
        },
    )

    async for c in _client(app):
        resp = await _override(c, inc.id, "unblock")
    assert resp.status_code == 200
    assert resp.json()["status"] == "overridden"
    assert (await read_ladder(redis, SK)).state.value == "NORMAL"
    assert await denylist.contains(redis, "dead-jti") is False  # denylist entry cleared


async def test_next_request_allowed_within_one_override(app, sf) -> None:
    # unblock takes effect immediately: the same (previously revoked) token now decodes and
    # would pass pre-forward (jti no longer denylisted, ladder NORMAL).
    inc = await _seed_incident(sf)
    redis = app.state.redis
    await denylist.add(redis, "jti-1")
    await redis.sadd(f"revoked_jti:{SK}", "jti-1")
    async for c in _client(app):
        await _override(c, inc.id, "unblock")

    claims = JWTClaims(sub=742, jti="jti-1", role="user")
    decision = await enforce.pre_forward(
        redis,
        Settings(jwt_secret=SECRET),
        session_key=SK,
        jwt_claims=claims,
        step_up_header=None,
        now_ts=1000.0,
    )
    assert decision.short_circuit is None  # allowed — not denylisted, ladder NORMAL


async def test_empty_reason_is_422(app, sf) -> None:
    inc = await _seed_incident(sf)
    async for c in _client(app):
        resp = await _override(c, inc.id, "acknowledge", reason="   ")
    assert resp.status_code == 422


async def test_two_overrides_two_audit_rows(app, sf) -> None:
    inc = await _seed_incident(sf)
    async for c in _client(app):
        await _override(c, inc.id, "acknowledge", reason="first look")
        await _override(c, inc.id, "false_positive", reason="benign on review")
    async with sf() as s:
        n = (await s.execute(select(func.count()).select_from(OverrideRow))).scalar_one()
    assert n == 2  # audit rows accumulate, never overwritten (rule 6)


async def test_acknowledge_sets_status_no_ladder_change(app, sf) -> None:
    inc = await _seed_incident(sf)
    redis = app.state.redis
    await redis.hset(
        ladder_key(SK),
        mapping={
            "state": "BLOCK",
            "score": 95,
            "last_signal_at": 1.0,
            "changed_at": 1.0,
            "signals_5m": 3,
        },
    )
    async for c in _client(app):
        resp = await _override(c, inc.id, "acknowledge")
    assert resp.json()["status"] == "acknowledged"
    assert (await read_ladder(redis, SK)).state.value == "BLOCK"  # unchanged


async def test_force_block_sets_block(app, sf) -> None:
    inc = await _seed_incident(sf)
    redis = app.state.redis
    async for c in _client(app):
        resp = await _override(c, inc.id, "force_block", reason="known bad actor")
    assert resp.status_code == 200
    assert (await read_ladder(redis, SK)).state.value == "BLOCK"


async def test_override_publishes_incident_updated(app, sf) -> None:
    # Implementation-Backend.md Phase 7.1: override publishes incident.updated (in addition
    # to session.changed) so a feed open elsewhere reflects the new status without a refetch.
    inc = await _seed_incident(sf)
    q = app.state.broadcaster.subscribe()
    async for c in _client(app):
        await _override(c, inc.id, "acknowledge", reason="looked into it")
    frames = []
    while not q.empty():
        frames.append(q.get_nowait())
    types = [f.split("\n", 1)[0] for f in frames]
    assert "event: incident.updated" in types
    assert "event: session.changed" in types
    updated_frame = next(f for f in frames if f.startswith("event: incident.updated"))
    assert '"status":"acknowledged"' in updated_frame
