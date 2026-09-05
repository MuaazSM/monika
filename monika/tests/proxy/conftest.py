"""Fixtures: a stub upstream (echoes what it received) and a monika app pointed at it,
both driven in-process with httpx.ASGITransport — no network, no docker."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.detection.d1_auth import AuthDetector
from app.detection.d2_enum import EnumDetector
from app.detection.d3_rate import RateDetector
from app.detection.d4_payload import PayloadDetector
from app.endpoints.loader import load_registry
from app.incidents import models as _models  # noqa: F401  (register tables)
from app.incidents.sse import Broadcaster
from app.proxy.middleware import router as proxy_router
from app.settings import Settings

_CONFIG = Path(__file__).resolve().parents[2] / "config" / "endpoints.yaml"


def make_stub_upstream() -> FastAPI:
    """Upstream that echoes method, path, query and the raw body it received."""
    up = FastAPI()

    @up.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(request: Request, path: str) -> dict[str, object]:
        raw = await request.body()
        return {
            "method": request.method,
            "path": "/" + path,
            "query": dict(request.query_params),
            "body_sha_len": len(raw),
            "body_text": raw.decode("utf-8", "replace"),
        }

    return up


@pytest.fixture
async def sqlite_session_factory() -> AsyncIterator[async_sessionmaker]:
    """In-memory SQLite with request_log created; shared across the test."""
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def monika_app(sqlite_session_factory: async_sessionmaker) -> AsyncIterator[FastAPI]:
    """A monika app whose http_client talks in-process to the stub upstream."""
    upstream = make_stub_upstream()
    upstream_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=upstream), base_url="http://upstream"
    )

    registry = load_registry(_CONFIG)
    app = FastAPI()
    app.state.settings = Settings(jwt_secret="test-secret")
    app.state.session_factory = sqlite_session_factory
    app.state.http_client = upstream_client
    app.state.redis = aioredis.FakeRedis(decode_responses=True)
    app.state.endpoints = registry
    app.state.detectors = [
        AuthDetector(registry.admin_subs),
        EnumDetector(),
        RateDetector(app.state.settings),
        PayloadDetector(),
    ]
    app.state.broadcaster = Broadcaster()
    app.state.explainer_queue = asyncio.Queue()
    app.include_router(proxy_router)

    yield app
    await app.state.redis.aclose()
    await upstream_client.aclose()


@pytest.fixture
async def client(monika_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=monika_app), base_url="http://monika"
    ) as c:
        yield c


def make_token(sub: int, secret: str, jti: str = "jti-1", role: str = "user") -> str:
    import jwt as _jwt

    return _jwt.encode({"sub": sub, "jti": jti, "role": role}, secret, algorithm="HS256")
