"""Detection engine: run every registered detector concurrently over one RequestContext.

A detector that raises is logged and contributes zero signals — one broken detector must
never take down the request or suppress the others (CLAUDE.md rule 4: detection is off the
enforcement path).
"""

from __future__ import annotations

import asyncio

import structlog
from redis.asyncio import Redis

from .base import Detector, RequestContext
from .signal import Signal

logger = structlog.get_logger(__name__)


async def run_detectors(
    detectors: list[Detector], ctx: RequestContext, redis: Redis
) -> list[Signal]:
    """Run all detectors with asyncio.gather and return a flat list of their signals."""
    results = await asyncio.gather(*(d.run(ctx, redis) for d in detectors), return_exceptions=True)
    signals: list[Signal] = []
    for detector, result in zip(detectors, results, strict=True):
        if isinstance(result, BaseException):
            logger.error(
                "detector.failed",
                detector=getattr(detector, "name", detector.__class__.__name__),
                request_id=ctx.request_id,
                error=str(result),
                error_type=type(result).__name__,
            )
            continue
        signals.extend(result)
    return signals
