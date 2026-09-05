"""Engine: concurrent run, flat signal list, and failure isolation (CLAUDE.md rule 4)."""

from __future__ import annotations

from datetime import UTC, datetime

from fakeredis import aioredis

from app.detection.base import RequestContext, ResponseContext
from app.detection.engine import run_detectors
from app.detection.signal import Signal


def _ctx() -> RequestContext:
    return RequestContext(
        request_id="r1",
        method="GET",
        path="/api/users/701",
        path_params={"id": "701"},
        query={},
        headers={},
        jwt=None,
        ip="1.2.3.4",
        response=ResponseContext(status=200, bytes=10, body_json=None),
        started_at=datetime.now(UTC),
        latency_ms=1.0,
    )


def _signal(cat: str) -> Signal:
    return Signal(
        category=cat,  # type: ignore[arg-type]
        severity=50,
        evidence={"k": "v"},
        request_id="r1",
        endpoint_id=None,
        session_key="ip:1.2.3.4",
    )


class OneSignal:
    name = "one"

    async def run(self, ctx, redis):
        return [_signal("auth")]


class TwoSignals:
    name = "two"

    async def run(self, ctx, redis):
        return [_signal("enum"), _signal("rate")]


class Boom:
    name = "boom"

    async def run(self, ctx, redis):
        raise RuntimeError("detector exploded")


async def test_flattens_signals_from_all_detectors() -> None:
    redis = aioredis.FakeRedis(decode_responses=True)
    signals = await run_detectors([OneSignal(), TwoSignals()], _ctx(), redis)
    assert len(signals) == 3
    assert {s.category for s in signals} == {"auth", "enum", "rate"}
    await redis.aclose()


async def test_failing_detector_is_isolated() -> None:
    redis = aioredis.FakeRedis(decode_responses=True)
    # Boom raises; the others must still contribute all their signals.
    signals = await run_detectors([OneSignal(), Boom(), TwoSignals()], _ctx(), redis)
    assert len(signals) == 3
    assert {s.category for s in signals} == {"auth", "enum", "rate"}
    await redis.aclose()


async def test_no_detectors_returns_empty() -> None:
    redis = aioredis.FakeRedis(decode_responses=True)
    assert await run_detectors([], _ctx(), redis) == []
    await redis.aclose()
