"""Table-driven tests for D3 (PRD §6.6, §12.1 boundaries)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fakeredis import aioredis

from app.detection.base import JWTClaims, RequestContext, ResponseContext
from app.detection.baselines import _rpm_key
from app.detection.d3_rate import RateDetector, _rate_key
from app.endpoints.models import EndpointConfig
from app.settings import Settings

SETTINGS = Settings(rate_floor_rpm=20)
NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
NOW_TS = NOW.timestamp()
MINUTE = int(NOW_TS // 60)
SK = "742"
IP = "1.2.3.4"

USERS_EP = EndpointConfig(
    method="GET",
    path_pattern="/api/users/{id}",
    id_param="id",
    owner_field="id",
    auth_required=True,
)
LOGIN_EP = EndpointConfig(method="POST", path_pattern="/api/login", auth_required=False)


def _ctx(ep, *, status=200, req_body=None) -> RequestContext:
    return RequestContext(
        request_id="r1",
        method=ep.method,
        path="/api/x",
        path_params={},
        query={},
        headers={},
        body_json=req_body,  # login username lives in the REQUEST body
        jwt=JWTClaims(sub=742, jti="j", role="user"),
        ip=IP,
        endpoint=ep,
        response=ResponseContext(status=status, bytes=10, body_json=None),
        started_at=NOW,
        latency_ms=1.0,
    )


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def _seed_rate(redis, ep, rpm, mean, std):
    await redis.set(_rate_key(SK, ep.endpoint_id, MINUTE), rpm)
    await redis.hset(_rpm_key(ep.endpoint_id), mapping={"mean": mean, "std": std, "n": 100})


async def _run(redis, ctx):
    return await RateDetector(SETTINGS).run(ctx, redis)


# ---- z-score boundary (rpm well above floor to isolate z) ------------------------------


async def test_z_2_9_does_not_fire(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=100, mean=71, std=10)  # z = 2.9
    assert await _run(redis, _ctx(USERS_EP)) == []


async def test_z_3_0_fires(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=100, mean=70, std=10)  # z = 3.0
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.category == "rate"
    assert sig.evidence["z_score"] == 3.0
    assert set(sig.evidence) == {
        "rpm",
        "baseline_mean",
        "baseline_std",
        "z_score",
        "deviation_ratio",
    }


# ---- floor veto ------------------------------------------------------------------------


async def test_19_rpm_never_fires(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=19, mean=0.1, std=1)  # z ~ 18.9, ratio huge
    assert await _run(redis, _ctx(USERS_EP)) == []


async def test_20_rpm_can_fire(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=20, mean=0.1, std=1)
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.evidence["rpm"] == 20


# ---- severity scaling ------------------------------------------------------------------


async def test_severity_40_at_3sigma(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=100, mean=70, std=10)  # z = 3
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.severity == 40


async def test_severity_85_at_10sigma(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=100, mean=0, std=10)  # z = 10
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.evidence["z_score"] == 10.0
    assert sig.severity == 85


async def test_severity_capped_85_at_20sigma(redis) -> None:
    await _seed_rate(redis, USERS_EP, rpm=300, mean=100, std=10)  # z = 20
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.evidence["z_score"] == 20.0
    assert sig.severity == 85


async def test_login_gets_plus_10(redis) -> None:
    await _seed_rate(redis, LOGIN_EP, rpm=100, mean=70, std=10)  # z = 3 -> base 40
    sigs = await _run(redis, _ctx(LOGIN_EP, req_body={"username": "u"}))
    rate = next(s for s in sigs if "z_score" in s.evidence)
    assert rate.severity == 50  # 40 + 10


# ---- credential stuffing ---------------------------------------------------------------


async def _login_ctx(status=401, username="user1"):
    return _ctx(LOGIN_EP, status=status, req_body={"username": username})


async def test_stuffing_fires_at_8_failures(redis) -> None:
    await redis.set(f"login_fail:{SK}:{MINUTE}", 7)  # this request's 401 makes 8
    sigs = await _run(redis, await _login_ctx())
    stuff = [s for s in sigs if "failures_60s" in s.evidence]
    assert len(stuff) == 1
    assert stuff[0].severity == 75
    assert stuff[0].evidence["failures_60s"] == 8


async def test_stuffing_does_not_fire_at_7_failures(redis) -> None:
    await redis.set(f"login_fail:{SK}:{MINUTE}", 6)  # this request's 401 makes 7
    sigs = await _run(redis, await _login_ctx())
    assert [s for s in sigs if "failures_60s" in s.evidence] == []


async def test_stuffing_fires_at_5_usernames(redis) -> None:
    await redis.sadd(f"login_users:{IP}:{MINUTE}", "a", "b", "c", "d")  # +current = 5
    sigs = await _run(redis, await _login_ctx(status=200, username="e"))
    stuff = [s for s in sigs if "failures_60s" in s.evidence]
    assert len(stuff) == 1
    assert stuff[0].evidence["usernames_attempted"] == 5
    assert stuff[0].evidence["failures_60s"] == 0  # 200s, no failures


async def test_stuffing_does_not_fire_at_4_usernames(redis) -> None:
    await redis.sadd(f"login_users:{IP}:{MINUTE}", "a", "b", "c")  # +current = 4
    sigs = await _run(redis, await _login_ctx(status=200, username="d"))
    assert [s for s in sigs if "failures_60s" in s.evidence] == []


async def test_stuffing_conditions_independent(redis) -> None:
    # failures alone (single username), 8 failures -> fires
    await redis.set(f"login_fail:{SK}:{MINUTE}", 7)
    sigs = await _run(redis, await _login_ctx(status=401, username="only"))
    assert any("failures_60s" in s.evidence for s in sigs)


# ---- ratio path: rpm >= 5*mean fires even when z < 3 ----------------------------------


async def test_ratio_5x_mean_fires_below_z3(redis) -> None:
    # mean 6, std 100 -> z = (30-6)/100 = 0.24 (well below 3), but 30 >= 5*6 -> fires.
    await _seed_rate(redis, USERS_EP, rpm=30, mean=6, std=100)
    (sig,) = await _run(redis, _ctx(USERS_EP))
    assert sig.evidence["z_score"] < 3.0
    assert sig.evidence["rpm"] == 30  # fired via the 5x-mean ratio path


async def test_ratio_just_below_5x_does_not_fire(redis) -> None:
    # rpm 29 vs mean 6 -> 29 < 30 (=5*6), and z=(29-6)/100=0.23 < 3 -> no fire.
    # (29 >= floor 20, so the floor is not what vetoes it.)
    await _seed_rate(redis, USERS_EP, rpm=29, mean=6, std=100)
    assert await _run(redis, _ctx(USERS_EP)) == []
