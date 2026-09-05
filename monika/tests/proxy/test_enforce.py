"""Enforcement wiring tests (PRD §5.2 / Figure 2, CLAUDE.md rule 4)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import jwt as _jwt
import pytest
from fakeredis import aioredis
from fastapi import FastAPI, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.detection.d1_auth import AuthDetector
from app.detection.d2_enum import EnumDetector
from app.detection.d3_rate import RateDetector
from app.detection.d4_payload import PayloadDetector
from app.endpoints.loader import load_registry
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import RequestLog
from app.incidents.sse import Broadcaster
from app.policy import denylist
from app.policy.ladder import LadderState, ladder_key
from app.proxy.middleware import router as proxy_router
from app.settings import Settings
from tests.proxy.conftest import _CONFIG

SECRET = "test-secret"


class CallCounter:
    def __init__(self) -> None:
        self.count = 0


def echo_upstream(counter: CallCounter) -> FastAPI:
    up = FastAPI()

    @up.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(request: Request, path: str) -> dict[str, object]:
        counter.count += 1
        return {"ok": True, "path": "/" + path}

    return up


def user_upstream(counter: CallCounter) -> FastAPI:
    """Returns a bulk user list with sensitive fields — a non-admin hit trips D1 (FLA) +
    D4 (bulk exposure), i.e. two categories -> BLOCK in one request (post D-12/D-13)."""
    up = FastAPI()

    @up.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def users(request: Request, path: str) -> list[dict[str, object]]:
        counter.count += 1
        return [{"id": 700 + i, "password_hash": "x", "ssn": f"{i}"} for i in range(25)]

    return up


async def _sqlite_factory() -> async_sessionmaker:
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


def build_app(upstream: FastAPI, redis, session_factory) -> FastAPI:
    registry = load_registry(_CONFIG)
    settings = Settings(jwt_secret=SECRET)
    app = FastAPI()
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.redis = redis
    app.state.endpoints = registry
    app.state.http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream), base_url="http://up"
    )
    app.state.detectors = [
        AuthDetector(registry.admin_subs),
        EnumDetector(),
        RateDetector(settings),
        PayloadDetector(),
    ]
    app.state.broadcaster = Broadcaster()
    app.state.explainer_queue = asyncio.Queue()
    app.include_router(proxy_router)
    return app


def token(sub: int, jti: str = "jti-1", ttl_minutes: int = 30) -> str:
    now = datetime.now(UTC)
    return _jwt.encode(
        {"sub": sub, "jti": jti, "role": "user", "exp": now + timedelta(minutes=ttl_minutes)},
        SECRET,
        algorithm="HS256",
    )


async def _set_state(redis, session_key: str, state: LadderState) -> None:
    await redis.hset(
        ladder_key(session_key),
        mapping={
            "state": state.value,
            "score": 0,
            "last_signal_at": datetime.now(UTC).timestamp(),
            "changed_at": datetime.now(UTC).timestamp(),
            "signals_5m": 0,
        },
    )


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def _client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://monika"
    ) as c:
        yield c
    await app.state.http_client.aclose()


# ---- blocked session -> 403, upstream never called -------------------------------------


async def test_blocked_session_gets_403_and_upstream_not_called(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(echo_upstream(counter), redis, sf)
    await _set_state(redis, "742", LadderState.BLOCK)
    async for c in _client(app):
        resp = await c.get("/api/products", headers={"authorization": f"Bearer {token(742)}"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "blocked"
    assert counter.count == 0  # upstream never called


# ---- revoked jti -> 401 pre-forward ---------------------------------------------------


async def test_revoked_jti_gets_401_preforward(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(echo_upstream(counter), redis, sf)
    await denylist.add(redis, "dead-jti")
    async for c in _client(app):
        resp = await c.get(
            "/api/products", headers={"authorization": f"Bearer {token(742, jti='dead-jti')}"}
        )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "token revoked"
    assert counter.count == 0


# ---- rate limit: 200 on request 10, 429 on request 11 ---------------------------------


async def test_rate_limited_at_request_11(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(echo_upstream(counter), redis, sf)
    await _set_state(redis, "742", LadderState.RATE_LIMIT)
    statuses = []
    last = None
    async for c in _client(app):
        for _ in range(11):
            last = await c.get(
                "/api/search?q=hello", headers={"authorization": f"Bearer {token(742)}"}
            )
            statuses.append(last.status_code)
    assert statuses[9] == 200  # request 10
    assert statuses[10] == 429  # request 11
    assert last is not None and "retry-after" in last.headers  # Retry-After present


# ---- challenge: 401 without header, 200 with a valid X-Step-Up -------------------------


async def test_challenge_without_header_401(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(echo_upstream(counter), redis, sf)
    await _set_state(redis, "742", LadderState.CHALLENGE)
    async for c in _client(app):
        resp = await c.get("/api/products", headers={"authorization": f"Bearer {token(742)}"})
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "StepUp"
    assert counter.count == 0


async def test_challenge_with_valid_stepup_200(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(echo_upstream(counter), redis, sf)
    await _set_state(redis, "742", LadderState.CHALLENGE)
    step_up = token(742, jti="stepup", ttl_minutes=5)
    async for c in _client(app):
        resp = await c.get(
            "/api/products",
            headers={"authorization": f"Bearer {token(742)}", "x-step-up": step_up},
        )
    assert resp.status_code == 200
    assert counter.count == 1


# ---- enforcement lag: triggering request is forwarded, only the NEXT is blocked -------


async def test_enforcement_lag_block_hits_next_request(redis) -> None:
    counter = CallCounter()
    sf = await _sqlite_factory()
    app = build_app(user_upstream(counter), redis, sf)
    tok = token(742)
    async for c in _client(app):
        # request 1: non-admin 742 hits admin/users -> D1 (FLA) + D4 (bulk exposure) -> BLOCK,
        # but THIS request still gets its upstream response.
        r1 = await c.get("/api/admin/users", headers={"authorization": f"Bearer {tok}"})
        # request 2: now the session is BLOCK -> 403 pre-forward.
        r2 = await c.get("/api/admin/users", headers={"authorization": f"Bearer {tok}"})
    assert r1.status_code == 200
    assert len(r1.json()) == 25  # got the real upstream body
    assert r2.status_code == 403
    assert counter.count == 1  # upstream called once (only the first, triggering request)

    # ladder is BLOCK, and the triggering request logged action_applied="allow"
    async with sf() as s:
        rows = list(
            (await s.execute(select(RequestLog).order_by(RequestLog.latency_ms.desc()))).scalars()
        )
    actions = {r.status_code: r.action_applied for r in rows}
    assert actions[200] == "allow"
    assert actions[403] == "block"
    assert (await redis.hget(ladder_key("742"), "state")) == "BLOCK"
