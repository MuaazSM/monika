"""Shared, cross-detector session state in Redis (no detector imports another).

D1 records the owner values it extracts for a session+endpoint here; D2 reads the distinct
count. Keeping it in a neutral module lets both detectors share the state without D2
importing d1_auth (CLAUDE.md rule 9 keeps the module graph acyclic).

Keys (CLAUDE.md §7):
  enum:{session_key}:{endpoint_id}        ZSET member=object_id   score=ts  TTL 300
  enum_owner:{session_key}:{endpoint_id}  ZSET member=owner_value score=ts  TTL 300
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import cast
from uuid import UUID

from redis.asyncio import Redis

WINDOW_SECONDS = 60
TTL_SECONDS = 300


def ids_key(session_key: str, endpoint_id: UUID) -> str:
    return f"enum:{session_key}:{endpoint_id}"


def owner_key(session_key: str, endpoint_id: UUID) -> str:
    return f"enum_owner:{session_key}:{endpoint_id}"


async def record_id(
    redis: Redis, session_key: str, endpoint_id: UUID, object_id: str, now_ts: float
) -> None:
    """Add the requested object id to the session's recent-ids ZSET (score = now)."""
    key = ids_key(session_key, endpoint_id)
    await redis.zadd(key, {object_id: now_ts})
    await redis.expire(key, TTL_SECONDS)


async def recent_ids(redis: Redis, session_key: str, endpoint_id: UUID, now_ts: float) -> list[str]:
    """Ids scored within the last WINDOW_SECONDS, in time (score-ascending) order.

    Older ids remain in Redis until the 300s TTL expires but are excluded from the window.
    """
    key = ids_key(session_key, endpoint_id)
    return cast("list[str]", await redis.zrangebyscore(key, now_ts - WINDOW_SECONDS, "+inf"))


async def record_owners(
    redis: Redis,
    session_key: str,
    endpoint_id: UUID,
    owners: Iterable[object],
    now_ts: float,
) -> None:
    """Record the owner values D1 extracted for this session+endpoint (score = now)."""
    mapping = {str(o): now_ts for o in owners if o is not None}
    if not mapping:
        return
    key = owner_key(session_key, endpoint_id)
    await redis.zadd(key, mapping)
    await redis.expire(key, TTL_SECONDS)


async def distinct_owners_60s(
    redis: Redis, session_key: str, endpoint_id: UUID, now_ts: float
) -> int:
    """Number of distinct owner values seen for this session+endpoint in the last 60s."""
    key = owner_key(session_key, endpoint_id)
    members = cast("list[str]", await redis.zrangebyscore(key, now_ts - WINDOW_SECONDS, "+inf"))
    return len(set(members))
