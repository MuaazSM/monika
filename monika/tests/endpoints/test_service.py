"""Endpoints risk-map service (PRD §13.1). risk_level is derived from incidents seen on
each endpoint: red (>=80), amber (any incident, >=30), else green."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.base import Base
from app.endpoints.loader import EndpointRegistry
from app.endpoints.models import EndpointConfig, EndpointUpdateIn
from app.endpoints.service import list_endpoints, update_endpoint
from app.incidents import models as _models  # noqa: F401
from app.incidents.models import EndpointConfigRow, IncidentRow

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
USERS = uuid4()
PRODUCTS = uuid4()
SEARCH = uuid4()


@pytest.fixture
async def sf():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _ep(eid, path, **kw):
    return EndpointConfigRow(
        id=eid,
        method=kw.get("method", "GET"),
        path_pattern=path,
        owner_field=kw.get("owner_field"),
        id_param=kw.get("id_param"),
        sensitive_fields=kw.get("sensitive_fields", []),
        baseline_rpm_mean=kw.get("rpm_mean", 0.0),
        baseline_rpm_std=kw.get("rpm_std", 0.0),
        baseline_resp_bytes=kw.get("resp_bytes", 0),
        auth_required=kw.get("auth_required", False),
        admin_only=kw.get("admin_only", False),
    )


def _inc(eid, score, *, minutes_ago=1):
    return IncidentRow(
        id=uuid4(),
        session_key="742",
        endpoint_id=eid,
        threat_type="BOLA_ENUMERATION",
        risk_score=score,
        confidence=70,
        action_taken="BLOCK",
        status="open",
        created_at=NOW - timedelta(minutes=minutes_ago),
        updated_at=NOW - timedelta(minutes=minutes_ago),
    )


async def _seed_endpoints(sf):
    async with sf() as s:
        s.add(_ep(USERS, "/api/users/{id}", auth_required=True, sensitive_fields=["ssn"]))
        s.add(_ep(PRODUCTS, "/api/products", sensitive_fields=["cost_price"], rpm_mean=12.5))
        s.add(_ep(SEARCH, "/api/search"))
        await s.commit()


async def test_risk_levels_reflect_incidents(sf) -> None:
    await _seed_endpoints(sf)
    async with sf() as s:
        s.add(_inc(USERS, 100))  # severe -> red
        s.add(_inc(PRODUCTS, 72))  # high, < 80 -> amber
        # SEARCH has no incident -> green
        await s.commit()

    rows = {e.path_pattern: e for e in await list_endpoints(sf, now=NOW)}
    assert rows["/api/users/{id}"].risk_level == "red"
    assert rows["/api/users/{id}"].max_risk_score == 100
    assert rows["/api/products"].risk_level == "amber"
    assert rows["/api/products"].max_risk_score == 72
    assert rows["/api/search"].risk_level == "green"
    assert rows["/api/search"].max_risk_score is None
    assert rows["/api/search"].incident_count == 0


async def test_max_score_across_multiple_incidents(sf) -> None:
    await _seed_endpoints(sf)
    async with sf() as s:
        s.add(_inc(USERS, 45))
        s.add(_inc(USERS, 88))  # the max is what decides the level
        await s.commit()
    rows = {e.path_pattern: e for e in await list_endpoints(sf, now=NOW)}
    assert rows["/api/users/{id}"].incident_count == 2
    assert rows["/api/users/{id}"].max_risk_score == 88
    assert rows["/api/users/{id}"].risk_level == "red"


async def test_stale_incidents_outside_window_are_ignored(sf) -> None:
    await _seed_endpoints(sf)
    async with sf() as s:
        s.add(_inc(USERS, 100, minutes_ago=45))  # older than the 30-min window
        await s.commit()
    rows = {e.path_pattern: e for e in await list_endpoints(sf, now=NOW)}
    assert rows["/api/users/{id}"].risk_level == "green"
    assert rows["/api/users/{id}"].incident_count == 0


async def test_baseline_snapshot_is_surfaced(sf) -> None:
    await _seed_endpoints(sf)
    rows = {e.path_pattern: e for e in await list_endpoints(sf, now=NOW)}
    assert rows["/api/products"].baseline_rpm_mean == 12.5
    assert rows["/api/users/{id}"].auth_required is True
    assert rows["/api/products"].sensitive_fields == ["cost_price"]


async def test_update_endpoint_writes_db_row_and_live_registry(sf) -> None:
    # A self-contained seed: the DB row's id must be the SAME uuid5 the registry derives, so
    # this deliberately doesn't reuse the shared _seed_endpoints() random ids.
    config = EndpointConfig(
        method="GET", path_pattern="/api/products", sensitive_fields=("cost_price",)
    )
    async with sf() as s:
        s.add(_ep(config.endpoint_id, "/api/products", sensitive_fields=["cost_price"]))
        await s.commit()
    registry = EndpointRegistry([config], admin_subs=[])

    body = EndpointUpdateIn(
        owner_field=None,
        sensitive_fields=["cost_price", "supplier_margin"],
        auth_required=True,
    )
    result = await update_endpoint(sf, registry, config.endpoint_id, body, now=NOW)
    assert result is not None
    assert result.sensitive_fields == ["cost_price", "supplier_margin"]
    assert result.auth_required is True

    # the display row in Postgres reflects the change too
    rows = {e.path_pattern: e for e in await list_endpoints(sf, now=NOW)}
    assert rows["/api/products"].sensitive_fields == ["cost_price", "supplier_margin"]
    assert rows["/api/products"].auth_required is True
    # and the live matcher used by detection sees it immediately
    matched, _ = registry.match("GET", "/api/products")
    assert matched is not None and matched.sensitive_fields == ("cost_price", "supplier_margin")


async def test_update_endpoint_unknown_id_returns_none(sf) -> None:
    await _seed_endpoints(sf)
    registry = EndpointRegistry([], admin_subs=[])
    result = await update_endpoint(
        sf,
        registry,
        uuid4(),
        EndpointUpdateIn(owner_field=None, sensitive_fields=[], auth_required=False),
        now=NOW,
    )
    assert result is None
