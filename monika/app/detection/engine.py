"""Detection engine: run the registered detectors over one RequestContext.

A detector that raises is logged and contributes zero signals — one broken detector must
never take down the request or suppress the others (CLAUDE.md rule 4: detection is off the
enforcement path).

The first detector (D1) is run to completion before the rest start, then the remainder run
concurrently with asyncio.gather (Implementation-Backend.md Phase 4.5: "run D1 first ... then
D2/D3/D4 with asyncio.gather"). D1 writes the owner values it extracted to Redis
(detection.enum_state) and D2 reads that same key to count distinct owners; running every
detector fully concurrently races D1's write against D2's read on the SAME request, so D2's
distinct_owners evidence could lag by one request. Sequencing D1 first removes that race.
"""

from __future__ import annotations

import asyncio

import structlog
from redis.asyncio import Redis

from .base import Detector, RequestContext
from .signal import Signal

logger = structlog.get_logger(__name__)


async def _run_one(
    detector: Detector, ctx: RequestContext, redis: Redis
) -> list[Signal] | BaseException:
    try:
        return await detector.run(ctx, redis)
    except BaseException as exc:  # isolate one detector's failure from the rest (rule 4)
        return exc


def _collect(
    signals: list[Signal],
    detector: Detector,
    result: list[Signal] | BaseException,
    ctx: RequestContext,
) -> None:
    if isinstance(result, BaseException):
        logger.error(
            "detector.failed",
            detector=getattr(detector, "name", detector.__class__.__name__),
            request_id=ctx.request_id,
            error=str(result),
            error_type=type(result).__name__,
        )
        return
    signals.extend(result)


async def run_detectors(
    detectors: list[Detector], ctx: RequestContext, redis: Redis
) -> list[Signal]:
    """Run the first detector alone, then the rest concurrently; return a flat signal list."""
    if not detectors:
        return []
    signals: list[Signal] = []
    head, *tail = detectors
    _collect(signals, head, await _run_one(head, ctx, redis), ctx)
    if tail:
        results = await asyncio.gather(*(_run_one(d, ctx, redis) for d in tail))
        for detector, result in zip(tail, results, strict=True):
            _collect(signals, detector, result, ctx)
    return signals
