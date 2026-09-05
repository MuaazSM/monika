"""Rolling mean/std maths and Redis-backed baseline writes (fakeredis)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fakeredis import aioredis

from app.detection.baselines import (
    baselines_ready,
    bucket_mean,
    bucket_std,
    read_bytes,
    read_rpm,
    record_request,
    running_mean_update,
)

# ---- pure maths ------------------------------------------------------------------------


def test_running_mean_first_sample() -> None:
    assert running_mean_update(0.0, 0, 100.0) == (100.0, 1)


def test_running_mean_sequence() -> None:
    mean, n = 0.0, 0
    for v in (10.0, 20.0, 30.0):
        mean, n = running_mean_update(mean, n, v)
    assert n == 3
    assert mean == pytest.approx(20.0)


def test_bucket_std_below_two_samples_is_zero() -> None:
    assert bucket_std([]) == 0.0
    assert bucket_std([7.0]) == 0.0  # first-bucket / n<2 case


def test_bucket_std_known_value() -> None:
    # sample stdev of [1, 3] is sqrt(2) ~= 1.4142
    assert bucket_std([1.0, 3.0]) == pytest.approx(1.41421356, rel=1e-6)


def test_bucket_mean_empty_is_zero() -> None:
    assert bucket_mean([]) == 0.0


# ---- Redis-backed ----------------------------------------------------------------------


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def test_first_request_snapshot(redis) -> None:
    eid = uuid4()
    snap = await record_request(redis, eid, resp_bytes=500, now_ts=600.0)
    assert snap.n == 1
    assert snap.rpm_mean == 1.0  # one bucket with a single request
    assert snap.rpm_std == 0.0  # n<2 -> std 0
    assert snap.bytes_mean == 500.0
    mean, std, n = await read_rpm(redis, eid)
    assert (mean, std, n) == (1.0, 0.0, 1)
    bmean, bn = await read_bytes(redis, eid)
    assert (bmean, bn) == (500.0, 1)


async def test_two_requests_same_minute(redis) -> None:
    eid = uuid4()
    await record_request(redis, eid, 100, now_ts=600.0)
    snap = await record_request(redis, eid, 300, now_ts=630.0)  # same minute (bucket 10)
    assert snap.n == 2
    assert snap.rpm_mean == 2.0  # one bucket, count 2
    assert snap.rpm_std == 0.0
    assert snap.bytes_mean == pytest.approx(200.0)  # running mean of 100,300


async def test_rpm_std_across_minutes(redis) -> None:
    eid = uuid4()
    # minute 10: 3 requests, minute 11: 1 request  -> counts {3,1}
    for _ in range(3):
        await record_request(redis, eid, 100, now_ts=600.0)
    snap = await record_request(redis, eid, 100, now_ts=660.0)
    assert snap.n == 4
    assert snap.rpm_mean == pytest.approx(2.0)  # mean of [1,3] / [3,1]
    assert snap.rpm_std == pytest.approx(1.41421356, rel=1e-6)


async def test_baselines_ready_gate(redis) -> None:
    a, b = uuid4(), uuid4()
    assert await baselines_ready(redis, [a, b]) is False
    # push a to 30 samples, b to 29
    for i in range(30):
        await record_request(redis, a, 100, now_ts=600.0 + i)
    for i in range(29):
        await record_request(redis, b, 100, now_ts=600.0 + i)
    assert await baselines_ready(redis, [a, b]) is False  # b short by one
    await record_request(redis, b, 100, now_ts=700.0)
    assert await baselines_ready(redis, [a, b]) is True
