"""Table-driven tests for D1 (PRD §6.4, DECISIONS.md D-10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import aioredis

from app.detection.base import JWTClaims, RequestContext, ResponseContext
from app.detection.d1_auth import AuthDetector, _auth_key
from app.endpoints.models import EndpointConfig

ADMIN_SUBS = {749}

USERS_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/users/{id}",
    id_param="id",
    owner_field="id",
    auth_required=True,
    sensitive_fields=("password_hash", "ssn", "api_key"),
    admin_only=False,
)
ORDERS_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/users/{id}/orders",
    id_param="id",
    owner_field="user_id",
    auth_required=True,
    sensitive_fields=(),
    admin_only=False,
)
PRODUCTS_EP = EndpointConfig(  # public: owner_field null
    method="GET",
    path_pattern="/api/products",
    owner_field=None,
    auth_required=False,
    sensitive_fields=("cost_price", "supplier_margin"),
)
ADMIN_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/admin/users",
    owner_field=None,
    auth_required=True,
    admin_only=True,
    sensitive_fields=("password_hash", "ssn"),
)


def _ctx(
    ep: EndpointConfig | None,
    *,
    sub: int | None,
    body,
    status: int = 200,
    path_params: dict[str, str] | None = None,
) -> RequestContext:
    jwt = JWTClaims(sub=sub, jti="j", role="user") if sub is not None else None
    return RequestContext(
        request_id="r1",
        method=ep.method if ep else "GET",
        path="/api/x",
        path_params=path_params or {},
        query={},
        headers={},
        jwt=jwt,
        ip="1.2.3.4",
        endpoint=ep,
        response=ResponseContext(status=status, bytes=10, body_json=body),
        started_at=datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC),
        latency_ms=1.0,
    )


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def _run(redis, ctx):
    return await AuthDetector(ADMIN_SUBS).run(ctx, redis)


async def test_fires_on_owner_mismatch(redis) -> None:
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.category == "auth"
    assert sig.evidence["jwt_sub"] == 742
    assert sig.evidence["requested_object"] == "701"
    assert sig.evidence["object_owner"] == 701
    assert set(sig.evidence) == {
        "jwt_sub",
        "requested_object",
        "object_owner",
        "sensitive_fields_present",
        "prior_auth_signals_5m",
    }


async def test_no_fire_when_owner_equals_sub(redis) -> None:
    ctx = _ctx(USERS_EP, sub=701, body={"id": 701}, path_params={"id": "701"})
    assert await _run(redis, ctx) == []


async def test_no_fire_on_public_endpoint(redis) -> None:
    ctx = _ctx(PRODUCTS_EP, sub=742, body=[{"id": 1}])
    assert await _run(redis, ctx) == []


async def test_no_fire_on_404(redis) -> None:
    ctx = _ctx(
        USERS_EP, sub=742, body={"detail": "not found"}, status=404, path_params={"id": "701"}
    )
    assert await _run(redis, ctx) == []


async def test_severity_70_without_sensitive_field(redis) -> None:
    # orders endpoint has no sensitive_fields
    ctx = _ctx(ORDERS_EP, sub=742, body=[{"user_id": 701}], path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.severity == 70
    assert sig.evidence["sensitive_fields_present"] is False


async def test_severity_85_with_sensitive_field(redis) -> None:
    ctx = _ctx(
        USERS_EP,
        sub=742,
        body={"id": 701, "password_hash": "x", "ssn": "y"},
        path_params={"id": "701"},
    )
    (sig,) = await _run(redis, ctx)
    assert sig.severity == 85
    assert sig.evidence["sensitive_fields_present"] is True


async def test_severity_95_at_exactly_3_prior_signals(redis) -> None:
    await redis.set(
        _auth_key("742", int(datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC).timestamp() // 60)), 3
    )
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701, "password_hash": "x"}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.evidence["prior_auth_signals_5m"] == 3
    assert sig.severity == 95


async def test_severity_85_at_2_prior_signals(redis) -> None:
    await redis.set(
        _auth_key("742", int(datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC).timestamp() // 60)), 2
    )
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701, "password_hash": "x"}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.evidence["prior_auth_signals_5m"] == 2
    assert sig.severity == 85


async def test_admin_member_does_not_trigger_bola(redis) -> None:
    ctx = _ctx(USERS_EP, sub=749, body={"id": 701}, path_params={"id": "701"})
    assert await _run(redis, ctx) == []


async def test_list_with_one_foreign_owner_fires(redis) -> None:
    body = [{"user_id": 742} for _ in range(9)] + [{"user_id": 701}]  # 1 of 10 foreign
    ctx = _ctx(ORDERS_EP, sub=742, body=body, path_params={"id": "742"})
    (sig,) = await _run(redis, ctx)
    assert sig.severity == 70
    assert sig.evidence["object_owner"] == 701


async def test_broken_auth_no_token_severity_60(redis) -> None:
    ctx = _ctx(USERS_EP, sub=None, body={"id": 701}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.severity == 60
    assert sig.evidence["reason"] == "no_or_invalid_token"


async def test_function_level_auth_non_admin(redis) -> None:
    ctx = _ctx(ADMIN_EP, sub=742, body=[{"id": 700}, {"id": 701}])
    (sig,) = await _run(redis, ctx)
    assert sig.severity == 70
    assert sig.evidence == {"jwt_sub": 742, "endpoint": "GET /api/admin/users", "admin_only": True}


async def test_prior_count_increments_on_fire(redis) -> None:
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701}, path_params={"id": "701"})
    await _run(redis, ctx)
    minute = int(datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC).timestamp() // 60)
    assert int(await redis.get(_auth_key("742", minute))) == 1


async def test_prior_auth_signals_expire_after_5_minutes(redis) -> None:
    # Seed 3 prior auth signals 6 minutes ago -> outside the 5-bucket window -> not counted,
    # so this mismatch scores 85 (sensitive) not 95. Boundary for AUTH_WINDOW_MINUTES.
    base = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
    six_min_ago = int((base - timedelta(minutes=6)).timestamp() // 60)
    await redis.set(_auth_key("742", six_min_ago), 3)
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701, "password_hash": "x"}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.evidence["prior_auth_signals_5m"] == 0  # 6-min-old signals excluded
    assert sig.severity == 85  # not 95


async def test_prior_auth_signals_counted_within_5_minutes(redis) -> None:
    # Same 3 prior signals but 4 minutes ago -> within window -> counted -> severity 95.
    base = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
    four_min_ago = int((base - timedelta(minutes=4)).timestamp() // 60)
    await redis.set(_auth_key("742", four_min_ago), 3)
    ctx = _ctx(USERS_EP, sub=742, body={"id": 701, "password_hash": "x"}, path_params={"id": "701"})
    (sig,) = await _run(redis, ctx)
    assert sig.evidence["prior_auth_signals_5m"] == 3
    assert sig.severity == 95
