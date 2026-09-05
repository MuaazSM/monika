"""Detector D2 — Enumeration (PRD §6.5).

Tracks the object ids a session requests against one endpoint. Fires when the session has
requested >= 5 distinct ids in the last 60s AND the access pattern looks like a sweep:
either a long monotonic run of ids, or access spanning several distinct owners.

Redis: enum:{session_key}:{endpoint_id} ZSET (managed by detection.enum_state). The
distinct-owner count comes from the owner values D1 recorded (enum_owner ZSET), read via
detection.enum_state — D2 does not import d1_auth.
"""

from __future__ import annotations

from itertools import pairwise

from redis.asyncio import Redis

from . import enum_state
from .base import RequestContext
from .context import derive_session_key
from .signal import Signal

COUNT_THRESHOLD = 5
RUN_THRESHOLD = 4
OWNER_THRESHOLD = 3


def longest_monotonic_run(values: list[int]) -> int:
    """Length of the longest maximal run of consecutive entries (in the given time order)
    whose numeric values are strictly monotonic — each strictly greater than its immediate
    predecessor (ascending) or strictly less (descending).

    "Consecutive" means adjacent positions in the sequence, not a value step of exactly 1;
    equal adjacent values break both runs. Examples on time-ordered id sequences:
      [700,701,702,703]        -> 4   (strictly ascending)
      [705,704,703]            -> 3   (strictly descending)
      [710,700,701,702,703]    -> 4   (the ascending tail)
      [700,705,701,706,702]    -> 2   (zigzag: no run longer than 2)
    """
    if not values:
        return 0
    best = asc = desc = 1
    for prev, cur in pairwise(values):
        asc = asc + 1 if cur > prev else 1
        desc = desc + 1 if cur < prev else 1
        best = max(best, asc, desc)
    return best


class EnumDetector:
    """D2. Stateless; all state is in Redis."""

    name = "d2_enum"

    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]:
        ep = ctx.endpoint
        if ep is None or ep.id_param is None:
            return []
        id_val = ctx.path_params.get(ep.id_param)
        if id_val is None:
            return []

        session_key = derive_session_key(ctx.jwt, ctx.ip)
        now_ts = ctx.started_at.timestamp()

        await enum_state.record_id(redis, session_key, ep.endpoint_id, id_val, now_ts)
        ids = await enum_state.recent_ids(redis, session_key, ep.endpoint_id, now_ts)
        count = len(ids)
        if count < COUNT_THRESHOLD:
            return []

        try:
            values = [int(x) for x in ids]
            run = longest_monotonic_run(values)
            first_id: object = values[0]
            last_id: object = values[-1]
        except ValueError:
            run = 1
            first_id, last_id = ids[0], ids[-1]

        distinct_owners = await enum_state.distinct_owners_60s(
            redis, session_key, ep.endpoint_id, now_ts
        )

        if not (run >= RUN_THRESHOLD or distinct_owners >= OWNER_THRESHOLD):
            return []

        severity = min(90, 50 + 5 * (count - COUNT_THRESHOLD))
        return [
            Signal(
                category="enum",
                severity=severity,
                evidence={
                    "ids_seen_60s": count,
                    "longest_sequential_run": run,
                    "distinct_owners": distinct_owners,
                    "first_id": first_id,
                    "last_id": last_id,
                },
                request_id=ctx.request_id,
                endpoint_id=ep.endpoint_id,
                session_key=session_key,
            )
        ]
