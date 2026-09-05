"""Table-driven tests for D2 (PRD §6.5, §12.1 boundaries)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fakeredis import aioredis

from app.detection import enum_state
from app.detection.base import JWTClaims, RequestContext, ResponseContext
from app.detection.d2_enum import EnumDetector, longest_monotonic_run
from app.endpoints.models import EndpointConfig

EP = EndpointConfig(
    method="GET",
    path_pattern="/api/users/{id}",
    id_param="id",
    owner_field="id",
    auth_required=True,
)
NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
NOW_TS = NOW.timestamp()
SK = "742"


def _ctx(current_id: str) -> RequestContext:
    return RequestContext(
        request_id="r1",
        method="GET",
        path=f"/api/users/{current_id}",
        path_params={"id": current_id},
        query={},
        headers={},
        jwt=JWTClaims(sub=742, jti="j", role="user"),
        ip="1.2.3.4",
        endpoint=EP,
        response=ResponseContext(status=200, bytes=10, body_json={"id": int(current_id)}),
        started_at=NOW,
        latency_ms=1.0,
    )


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def _seed_ids(redis, ids_with_offsets: list[tuple[int, float]]) -> None:
    """Seed the enum ZSET with (id, score_offset_from_now)."""
    key = enum_state.ids_key(SK, EP.endpoint_id)
    await redis.zadd(key, {str(i): NOW_TS + off for i, off in ids_with_offsets})


async def _seed_owners(redis, owners: list[int]) -> None:
    await enum_state.record_owners(redis, SK, EP.endpoint_id, owners, NOW_TS)


async def _run(redis, ctx):
    return await EnumDetector().run(ctx, redis)


# ---- pure run maths --------------------------------------------------------------------


def test_run_ascending() -> None:
    assert longest_monotonic_run([700, 701, 702, 703]) == 4


def test_run_descending() -> None:
    assert longest_monotonic_run([705, 704, 703]) == 3


def test_run_zigzag() -> None:
    assert longest_monotonic_run([700, 705, 701, 706, 702]) == 2


def test_run_tail() -> None:
    assert longest_monotonic_run([710, 700, 701, 702, 703]) == 4


# ---- count boundary --------------------------------------------------------------------


async def test_does_not_fire_at_4_ids(redis) -> None:
    await _seed_ids(redis, [(700, -30), (701, -20), (702, -10)])
    assert await _run(redis, _ctx("703")) == []  # 4 total -> below count threshold


async def test_fires_at_5_ids(redis) -> None:
    await _seed_ids(redis, [(700, -40), (701, -30), (702, -20), (703, -10)])
    (sig,) = await _run(redis, _ctx("704"))  # 5 ascending
    assert sig.category == "enum"
    assert sig.evidence["ids_seen_60s"] == 5
    assert set(sig.evidence) == {
        "ids_seen_60s",
        "longest_sequential_run",
        "distinct_owners",
        "first_id",
        "last_id",
    }


# ---- run boundary (count>=5, owners<3) -------------------------------------------------


async def test_fires_on_run_of_4(redis) -> None:
    await _seed_ids(redis, [(710, -40), (700, -30), (701, -20), (702, -10)])
    (sig,) = await _run(redis, _ctx("703"))  # [710,700,701,702,703] run tail = 4
    assert sig.evidence["longest_sequential_run"] == 4


async def test_does_not_fire_on_run_of_3(redis) -> None:
    await _seed_ids(redis, [(710, -40), (720, -30), (700, -20), (701, -10)])
    # [710,720,700,701,702] longest run = 3; owners default (owner_field=id) recorded? no.
    assert await _run(redis, _ctx("702")) == []


# ---- owner boundary (count>=5, run<4) --------------------------------------------------


async def _zigzag_ids(redis) -> None:
    # run length 2 throughout
    await _seed_ids(redis, [(700, -40), (705, -30), (701, -20), (706, -10)])


async def test_fires_on_3_distinct_owners(redis) -> None:
    await _zigzag_ids(redis)
    await _seed_owners(redis, [901, 902, 903])
    (sig,) = await _run(redis, _ctx("702"))  # current 702 keeps zigzag, run<4
    assert sig.evidence["distinct_owners"] >= 3
    assert sig.evidence["longest_sequential_run"] < 4


async def test_does_not_fire_on_2_distinct_owners(redis) -> None:
    await _zigzag_ids(redis)
    await _seed_owners(redis, [901, 902])
    assert await _run(redis, _ctx("702")) == []


async def test_five_ids_neither_monotonic_nor_multiowner(redis) -> None:
    await _zigzag_ids(redis)
    await _seed_owners(redis, [901])  # single owner
    assert await _run(redis, _ctx("702")) == []


# ---- severity --------------------------------------------------------------------------


async def test_severity_50_at_5(redis) -> None:
    await _seed_ids(redis, [(700 + i, -50 + i) for i in range(4)])
    (sig,) = await _run(redis, _ctx("704"))
    assert sig.evidence["ids_seen_60s"] == 5
    assert sig.severity == 50


async def test_severity_75_at_10(redis) -> None:
    await _seed_ids(redis, [(700 + i, -50 + i) for i in range(9)])
    (sig,) = await _run(redis, _ctx("709"))
    assert sig.evidence["ids_seen_60s"] == 10
    assert sig.severity == 75


async def test_severity_capped_90_at_20(redis) -> None:
    await _seed_ids(redis, [(700 + i, -55 + i) for i in range(19)])
    (sig,) = await _run(redis, _ctx("719"))
    assert sig.evidence["ids_seen_60s"] == 20
    assert sig.severity == 90


# ---- window exclusion ------------------------------------------------------------------


async def test_old_ids_excluded_despite_ttl(redis) -> None:
    # 3 ids older than 60s + 3 recent; after current there are 4 recent -> below threshold.
    await _seed_ids(redis, [(600, -120), (601, -110), (602, -100)])  # old
    await _seed_ids(redis, [(700, -30), (701, -20), (702, -10)])  # recent
    assert await _run(redis, _ctx("703")) == []  # 4 in window (old excluded)
    # the old ids are still present in the ZSET (TTL 300, not removed)
    total = await redis.zcard(enum_state.ids_key(SK, EP.endpoint_id))
    assert total == 7  # 3 old + 3 recent + current
