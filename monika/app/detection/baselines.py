"""Per-endpoint rolling baselines and per-request rate counters in Redis (PRD §6.3, §7).

Redis is authoritative (DECISIONS.md D-03). Keys (CLAUDE.md §7):
  baseline:{endpoint_id}:rpm    HASH {mean, std, n}
  baseline:{endpoint_id}:bytes  HASH {mean, n}
  rate:{session_key}:{endpoint_id}:{minute}  INT  TTL 120
  rate:{session_key}:{minute}                INT  TTL 120

Window: 10 minutes of 1-minute buckets. `n` in both hashes is the running count of
requests observed for the endpoint — it is what `baselines_ready` gates on (>=30).
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from uuid import UUID

from redis.asyncio import Redis

WINDOW_MINUTES = 10
BUCKET_TTL = 660  # 11 minutes: keeps all 10 window buckets alive
RATE_TTL = 120
READY_MIN_SAMPLES = 30


# ---- pure maths (unit-tested with no Redis) --------------------------------------------


def running_mean_update(old_mean: float, old_n: int, value: float) -> tuple[float, int]:
    """Incremental mean. First sample (old_n==0) returns (value, 1)."""
    new_n = old_n + 1
    new_mean = old_mean + (value - old_mean) / new_n
    return new_mean, new_n


def bucket_mean(counts: list[float]) -> float:
    """Mean of per-minute request counts; 0.0 if the window is empty."""
    return statistics.fmean(counts) if counts else 0.0


def bucket_std(counts: list[float]) -> float:
    """Sample std of per-minute counts. 0.0 when fewer than 2 samples (n<2 case)."""
    if len(counts) < 2:
        return 0.0
    return statistics.stdev(counts)


# ---- Redis-backed reads/writes ---------------------------------------------------------


@dataclass(slots=True)
class BaselineSnapshot:
    """What a baseline write produced — also what gets mirrored to Postgres."""

    rpm_mean: float
    rpm_std: float
    bytes_mean: float
    n: int


def _rpm_key(endpoint_id: UUID) -> str:
    return f"baseline:{endpoint_id}:rpm"


def _bytes_key(endpoint_id: UUID) -> str:
    return f"baseline:{endpoint_id}:bytes"


def _bucket_key(endpoint_id: UUID, minute: int) -> str:
    return f"baseline:{endpoint_id}:bucket:{minute}"


async def record_request(
    redis: Redis, endpoint_id: UUID, resp_bytes: int, now_ts: float
) -> BaselineSnapshot:
    """Update rolling baselines for one observed request. Returns the new snapshot."""
    minute = int(now_ts // 60)

    # 1. bump this minute's request-count bucket
    bkey = _bucket_key(endpoint_id, minute)
    await redis.incr(bkey)
    await redis.expire(bkey, BUCKET_TTL)

    # 2. running mean of response bytes + running sample count n
    raw = await redis.hgetall(_bytes_key(endpoint_id))
    old_mean = float(raw.get("mean", 0.0))
    old_n = int(raw.get("n", 0))
    bytes_mean, n = running_mean_update(old_mean, old_n, float(resp_bytes))

    # 3. rpm mean/std over the last WINDOW_MINUTES buckets that still exist
    keys = [_bucket_key(endpoint_id, minute - i) for i in range(WINDOW_MINUTES)]
    vals = await redis.mget(keys)
    counts = [float(v) for v in vals if v is not None]
    rpm_mean = bucket_mean(counts)
    rpm_std = bucket_std(counts)

    # 4. persist both hashes (n identical in both — the running request count)
    await redis.hset(_rpm_key(endpoint_id), mapping={"mean": rpm_mean, "std": rpm_std, "n": n})
    await redis.hset(_bytes_key(endpoint_id), mapping={"mean": bytes_mean, "n": n})

    return BaselineSnapshot(rpm_mean=rpm_mean, rpm_std=rpm_std, bytes_mean=bytes_mean, n=n)


async def read_rpm(redis: Redis, endpoint_id: UUID) -> tuple[float, float, int]:
    """(mean, std, n) for requests-per-minute; zeros if unseen."""
    raw = await redis.hgetall(_rpm_key(endpoint_id))
    return (
        float(raw.get("mean", 0.0)),
        float(raw.get("std", 0.0)),
        int(raw.get("n", 0)),
    )


async def read_bytes(redis: Redis, endpoint_id: UUID) -> tuple[float, int]:
    """(mean, n) for response bytes; zeros if unseen."""
    raw = await redis.hgetall(_bytes_key(endpoint_id))
    return float(raw.get("mean", 0.0)), int(raw.get("n", 0))


async def bump_rate_counters(
    redis: Redis, session_key: str, endpoint_id: UUID, now_ts: float
) -> tuple[int, int]:
    """Increment the per-(session,endpoint,minute) and per-(session,minute) counters.

    Both are INT with TTL 120 (CLAUDE.md §7). Returns the two post-increment values.
    """
    minute = int(now_ts // 60)
    ep_key = f"rate:{session_key}:{endpoint_id}:{minute}"
    sess_key = f"rate:{session_key}:{minute}"
    ep_val = await redis.incr(ep_key)
    await redis.expire(ep_key, RATE_TTL)
    sess_val = await redis.incr(sess_key)
    await redis.expire(sess_key, RATE_TTL)
    return ep_val, sess_val


async def baselines_ready(redis: Redis, endpoint_ids: list[UUID]) -> bool:
    """True once every configured endpoint has n >= 30 (dashboard Learning badge)."""
    if not endpoint_ids:
        return False
    for eid in endpoint_ids:
        _, _, n = await read_rpm(redis, eid)
        if n < READY_MIN_SAMPLES:
            return False
    return True
