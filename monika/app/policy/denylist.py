"""JWT jti denylist (PRD §5.2, §8.1). The only pre-forward hard check in the proxy.

Backed by the Redis SET denylist:jti. Entering REVOKE denylists the token's jti (see
policy.ladder.apply_signals, which also resets the ladder per DECISIONS.md D-08).
"""

from __future__ import annotations

from redis.asyncio import Redis

DENYLIST_KEY = "denylist:jti"


async def add(redis: Redis, jti: str) -> None:
    """Denylist a jti — the token is dead until re-login."""
    await redis.sadd(DENYLIST_KEY, jti)


async def contains(redis: Redis, jti: str) -> bool:
    """True if the jti is denylisted (checked pre-forward for REVOKE)."""
    return bool(await redis.sismember(DENYLIST_KEY, jti))


async def remove(redis: Redis, jti: str) -> None:
    """Remove a jti from the denylist (analyst unblock)."""
    await redis.srem(DENYLIST_KEY, jti)
