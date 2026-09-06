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


async def test_first_detector_completes_before_the_rest_start() -> None:
    # Implementation-Backend.md Phase 4.5: D1 must finish (including its Redis writes)
    # before D2/D3/D4 start, so a shared Redis read in one of the others reflects D1's write
    # from the SAME request rather than racing it.
    order: list[str] = []

    class First:
        name = "first"

        async def run(self, ctx, redis):
            order.append("first-start")
            await redis.set("shared", "written-by-first")
            order.append("first-end")
            return []

    class Second:
        name = "second"

        async def run(self, ctx, redis):
            order.append("second-start")
            value = await redis.get("shared")
            order.append(f"second-saw:{value}")
            return []

    redis = aioredis.FakeRedis(decode_responses=True)
    await run_detectors([First(), Second()], _ctx(), redis)
    await redis.aclose()
    assert order == ["first-start", "first-end", "second-start", "second-saw:written-by-first"]
