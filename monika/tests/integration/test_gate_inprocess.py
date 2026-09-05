"""Gate 1 scenario tests (PRD §12.3 / §11.4): benign -> zero incidents; IDOR -> BLOCK+REVOKE.

Runs the whole pipeline (proxy -> detectors -> scorer -> ladder -> incident store) in-process
against a stub upstream that behaves like the demo API, with fakeredis + SQLite. This is the
end-to-end assertion the per-detector unit tests structurally cannot make.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import jwt as _jwt
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.detection.d1_auth import AuthDetector
from app.detection.d2_enum import EnumDetector
from app.detection.d3_rate import RateDetector
from app.detection.d4_payload import PayloadDetector
from app.endpoints.loader import load_registry
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import IncidentRow, SignalRow
from app.incidents.sse import Broadcaster
from app.policy import denylist
from app.policy.ladder import ladder_key
from app.proxy.middleware import router as proxy_router
from app.settings import Settings
from tests.proxy.conftest import _CONFIG

SECRET = "test-secret"


def demo_upstream() -> FastAPI:
    """A stand-in for the demo API: user rows carry password_hash; products carry cost_price."""
    up = FastAPI()

    @up.get("/api/users/{uid}")
    async def get_user(uid: int) -> dict[str, object]:
        return {"id": uid, "username": f"user{uid}", "password_hash": "x", "ssn": f"{uid}"}

    @up.get("/api/users/{uid}/orders")
    async def get_orders(uid: int) -> list[dict[str, object]]:
        return [{"id": i, "user_id": uid, "item": "x"} for i in range(10)]

    @up.get("/api/products")
    async def products(page: int = 1) -> dict[str, object]:
        return {"page": page, "results": [{"id": i, "cost_price": i} for i in range(20)]}

    @up.post("/api/login")
    async def login() -> dict[str, object]:
        return {"access_token": "stub", "token_type": "bearer"}

    return up


def build_app(redis, session_factory) -> FastAPI:
    registry = load_registry(_CONFIG)
    settings = Settings(jwt_secret=SECRET, rate_floor_rpm=20)
    app = FastAPI()
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.redis = redis
    app.state.endpoints = registry
    app.state.http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=demo_upstream()), base_url="http://up"
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


def token(sub: int, jti: str = "j") -> str:
    return _jwt.encode(
        {"sub": sub, "jti": jti, "role": "user", "exp": datetime.now(UTC) + timedelta(minutes=30)},
        SECRET,
        algorithm="HS256",
    )


async def _factory() -> async_sessionmaker:
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


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


async def _count(sf, model) -> int:
    async with sf() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar_one()


# ---- Gate 1 criterion 2: benign produces zero incidents >= 30 -------------------------


async def test_benign_produces_no_incident(redis) -> None:
    sf = await _factory()
    app = build_app(redis, sf)
    async for c in _client(app):
        for uid in (703, 711, 720):
            hdr = {"authorization": f"Bearer {token(uid)}", "x-monika-label": "benign"}
            for page in range(1, 6):  # own profile, own orders, product paging
                await c.get(f"/api/users/{uid}", headers=hdr)
                await c.get(f"/api/users/{uid}/orders", headers=hdr)
                await c.get(f"/api/products?page={page}", headers=hdr)
    async with sf() as s:
        ge30 = (
            await s.execute(
                select(func.count()).select_from(IncidentRow).where(IncidentRow.risk_score >= 30)
            )
        ).scalar_one()
    assert ge30 == 0


# ---- Gate 1 criterion 1: IDOR -> BOLA_ENUMERATION, score>=90, >=3 signals, BLOCK->REVOKE


async def test_idor_sweep_blocks_then_revokes(redis) -> None:
    sf = await _factory()
    app = build_app(redis, sf)
    hdr = {"authorization": f"Bearer {token(742)}", "x-monika-label": "attack:idor"}
    async for c in _client(app):
        for oid in range(700, 731):  # 742 sweeps 700..730
            await c.get(f"/api/users/{oid}", headers=hdr)

    # exactly one incident, BOLA_ENUMERATION, score >= 90
    assert await _count(sf, IncidentRow) == 1
    async with sf() as s:
        inc = (await s.execute(select(IncidentRow))).scalar_one()
        n_signals = (
            await s.execute(
                select(func.count()).select_from(SignalRow).where(SignalRow.incident_id == inc.id)
            )
        ).scalar_one()
    assert inc.threat_type == "BOLA_ENUMERATION"
    assert inc.risk_score >= 90
    assert n_signals >= 3  # Gate 1: >= 3 signals

    # ladder reached BLOCK then REVOKE (jti denylisted, ladder reset to OBSERVE per D-08/D-14)
    assert await denylist.contains(redis, "j") is True
    assert (await redis.hget(ladder_key("742"), "state")) == "OBSERVE"  # post-revoke reset
