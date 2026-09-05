"""Fixtures for incident service/router tests: in-memory SQLite + fakeredis + a monika app."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from fakeredis import aioredis
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import EndpointConfigRow, SessionRow
from app.incidents.router import router as incidents_router

ENDPOINT_ID = uuid4()
SESSION_KEY = "742"


@dataclass
class Sig:
    """A structural signal for the service (category/severity/evidence + persisted fields)."""

    category: str
    severity: int
    request_id: str = "r1"
    session_key: str = SESSION_KEY
    endpoint_id: UUID | None = ENDPOINT_ID
    evidence: dict[str, Any] = field(default_factory=lambda: {"k": "v"})


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker]:
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    # Seed FK parents: an endpoint_config row and a session row.
    async with sf() as s:
        s.add(
            EndpointConfigRow(
                id=ENDPOINT_ID,
                method="GET",
                path_pattern="/api/users/{id}",
                sensitive_fields=[],
                auth_required=True,
                admin_only=False,
            )
        )
        s.add(
            SessionRow(
                session_key=SESSION_KEY,
                ladder_state="OBSERVE",
                current_score=0,
                last_signal_at=datetime.now(UTC),
                state_changed_at=datetime.now(UTC),
            )
        )
        await s.commit()
    yield sf
    await engine.dispose()


@pytest.fixture
async def app(session_factory: async_sessionmaker) -> AsyncIterator[FastAPI]:
    application = FastAPI()
    application.state.session_factory = session_factory
    application.state.redis = aioredis.FakeRedis(decode_responses=True)
    application.include_router(incidents_router)
    yield application
    await application.state.redis.aclose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://monika"
    ) as c:
        yield c
