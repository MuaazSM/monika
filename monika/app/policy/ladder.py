"""Response ladder state machine (PRD §8.1, DECISIONS.md D-01/D-04/D-05/D-08).

The §8.1 transition table is encoded as DATA in TRANSITIONS (tests iterate it). The live
escalation/decay logic follows D-01:

  * Escalation: new_state = max(current, band_floor(score), signal_floor) by ladder ordinal,
    applied as at most ONE transition per request (a jump, e.g. NORMAL->BLOCK at score 100,
    is a single transition). REVOKE is reachable ONLY from BLOCK.
  * Decay: exactly one rung down, on the §8.1 timings, each divided by the time divisor so
    demos run fast.

State lives in Redis hash ladder:{session_key} (D-05 fields incl. signals_5m). The SESSION
row is upserted on every change for audit only (D-04) and never read by the proxy.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import denylist


class LadderState(enum.StrEnum):
    NORMAL = "NORMAL"
    OBSERVE = "OBSERVE"
    RATE_LIMIT = "RATE_LIMIT"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"
    REVOKE = "REVOKE"


# Ladder ordinal — the ordering escalation maxes over and decay steps down.
LADDER_ORDER: list[LadderState] = [
    LadderState.NORMAL,
    LadderState.OBSERVE,
    LadderState.RATE_LIMIT,
    LadderState.CHALLENGE,
    LadderState.BLOCK,
    LadderState.REVOKE,
]
_ORD: dict[LadderState, int] = {s: i for i, s in enumerate(LADDER_ORDER)}

# Decay: from_state -> (seconds without signals, next_state one rung down). §8.1.
DECAY_SECONDS: dict[LadderState, tuple[int, LadderState]] = {
    LadderState.OBSERVE: (300, LadderState.NORMAL),  # 5 min
    LadderState.RATE_LIMIT: (600, LadderState.OBSERVE),  # 10 min
    LadderState.CHALLENGE: (600, LadderState.RATE_LIMIT),  # 10 min
    LadderState.BLOCK: (1800, LadderState.CHALLENGE),  # 30 min
}

_AUTH_EXPOSURE = frozenset({"auth", "exposure"})


# --------------------------------------------------------------------------------------
# §8.1 table encoded as data (tests iterate this)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TriggerContext:
    """Everything a §8.1 trigger predicate may inspect."""

    score: int = 0
    signals_5m: int = 0
    categories: frozenset[str] = frozenset()
    challenge_passed: bool = False
    elapsed_seconds: float = 0.0
    divisor: int = 1


@dataclass(frozen=True)
class Transition:
    from_state: LadderState
    to_state: LadderState
    kind: str  # "escalate" | "decay"
    trigger: Callable[[TriggerContext], bool]
    enforcement: str


TRANSITIONS: list[Transition] = [
    Transition(
        LadderState.NORMAL,
        LadderState.OBSERVE,
        "escalate",
        lambda c: c.score >= 30,
        "Verbose logging; no user impact",
    ),
    Transition(
        LadderState.OBSERVE,
        LadderState.RATE_LIMIT,
        "escalate",
        lambda c: c.score >= 60 or c.signals_5m >= 2,
        "10 req/min per session; excess -> 429 with Retry-After",
    ),
    Transition(
        LadderState.RATE_LIMIT,
        LadderState.CHALLENGE,
        "escalate",
        lambda c: c.score >= 80 or c.signals_5m >= 3,
        "401 with WWW-Authenticate: StepUp; passes with fresh X-Step-Up token",
    ),
    Transition(
        LadderState.CHALLENGE,
        LadderState.BLOCK,
        "escalate",
        lambda c: c.score >= 90 or (c.challenge_passed and bool(c.categories)),
        "403 for all requests; body includes incident_id",
    ),
    Transition(
        LadderState.BLOCK,
        LadderState.REVOKE,
        "escalate",
        lambda c: c.score >= 100 or bool(c.categories & _AUTH_EXPOSURE),
        "jti added to denylist; token dead until re-login; new session starts at OBSERVE",
    ),
    Transition(
        LadderState.OBSERVE,
        LadderState.NORMAL,
        "decay",
        lambda c: c.elapsed_seconds >= 300 / c.divisor,
        "5 min without signals",
    ),
    Transition(
        LadderState.RATE_LIMIT,
        LadderState.OBSERVE,
        "decay",
        lambda c: c.elapsed_seconds >= 600 / c.divisor,
        "10 min without signals",
    ),
    Transition(
        LadderState.CHALLENGE,
        LadderState.RATE_LIMIT,
        "decay",
        lambda c: c.elapsed_seconds >= 600 / c.divisor,
        "10 min without signals",
    ),
    Transition(
        LadderState.BLOCK,
        LadderState.CHALLENGE,
        "decay",
        lambda c: c.elapsed_seconds >= 1800 / c.divisor,
        "30 min without signals",
    ),
]


# --------------------------------------------------------------------------------------
# pure escalation / decay (D-01)
# --------------------------------------------------------------------------------------


def band_floor(score: int) -> LadderState:
    """The minimum rung a score alone justifies (D-01)."""
    if score >= 90:
        return LadderState.BLOCK
    if score >= 80:
        return LadderState.CHALLENGE
    if score >= 60:
        return LadderState.RATE_LIMIT
    if score >= 30:
        return LadderState.OBSERVE
    return LadderState.NORMAL


def _signal_floor(signals_5m: int, challenge_passed: bool, has_signal: bool) -> LadderState:
    """The minimum rung the §8.1 signal-count triggers justify."""
    floor = LadderState.NORMAL
    if signals_5m >= 2:
        floor = LadderState.RATE_LIMIT
    if signals_5m >= 3:
        floor = LadderState.CHALLENGE
    if challenge_passed and has_signal:  # any signal after a passed challenge
        floor = LadderState.BLOCK
    return floor


def _max_state(*states: LadderState) -> LadderState:
    return max(states, key=lambda s: _ORD[s])


# DECISIONS.md D-13: a single-category request only escalates to RATE_LIMIT unless the
# score is already severe (>=90). CHALLENGE/BLOCK need correlation (>=2 distinct categories)
# or a >=90 score. This keeps a single detector from freezing detection (CHALLENGE/BLOCK
# 401/403 pre-forward) so a sweep can forward and accumulate correlated signals.
CORRELATION_MIN_CATEGORIES = 2
SINGLE_CATEGORY_SEVERE_SCORE = 90


def escalate(
    current: LadderState,
    *,
    score: int,
    signals_5m: int,
    categories: Iterable[str],
    challenge_passed: bool = False,
) -> LadderState:
    """New state after a request's signals (D-01, amended by D-13). At most one transition;
    REVOKE only from BLOCK. Never downgrades (maxed against current)."""
    cats = frozenset(categories)
    # REVOKE is reachable only from BLOCK, on score==100 or an auth/exposure signal.
    if current == LadderState.BLOCK and (score >= 100 or bool(cats & _AUTH_EXPOSURE)):
        return LadderState.REVOKE

    target = _max_state(
        current,
        band_floor(score),
        _signal_floor(signals_5m, challenge_passed, bool(cats)),
    )
    # D-13 correlation cap: a lone moderate signal throttles (RATE_LIMIT) rather than
    # freezing the session at CHALLENGE/BLOCK, so detection keeps running on the sweep.
    if len(cats) < CORRELATION_MIN_CATEGORIES and score < SINGLE_CATEGORY_SEVERE_SCORE:
        ceiling = _max_state(current, LadderState.RATE_LIMIT)
        if _ORD[target] > _ORD[ceiling]:
            target = ceiling
    return target


def decay(current: LadderState, elapsed_seconds: float, divisor: int) -> LadderState:
    """One rung down if enough quiet time has passed; otherwise unchanged."""
    entry = DECAY_SECONDS.get(current)
    if entry is None:  # NORMAL and REVOKE do not decay
        return current
    seconds, lower = entry
    return lower if elapsed_seconds >= seconds / divisor else current


# --------------------------------------------------------------------------------------
# Redis persistence + SESSION audit
# --------------------------------------------------------------------------------------


@dataclass
class LadderRecord:
    state: LadderState = LadderState.NORMAL
    score: int = 0
    last_signal_at: float = 0.0
    changed_at: float = 0.0
    signals_5m: int = 0


def ladder_key(session_key: str) -> str:
    return f"ladder:{session_key}"


async def read_ladder(redis: Redis, session_key: str) -> LadderRecord:
    raw = await redis.hgetall(ladder_key(session_key))
    if not raw:
        return LadderRecord()
    return LadderRecord(
        state=LadderState(str(raw.get("state", "NORMAL"))),
        score=int(raw.get("score", 0)),
        last_signal_at=float(raw.get("last_signal_at", 0.0)),
        changed_at=float(raw.get("changed_at", 0.0)),
        signals_5m=int(raw.get("signals_5m", 0)),
    )


async def write_ladder(redis: Redis, session_key: str, rec: LadderRecord) -> None:
    await redis.hset(
        ladder_key(session_key),
        mapping={
            "state": rec.state.value,
            "score": rec.score,
            "last_signal_at": rec.last_signal_at,
            "changed_at": rec.changed_at,
            "signals_5m": rec.signals_5m,
        },
    )


async def _upsert_session(
    session_factory: async_sessionmaker[AsyncSession] | None,
    session_key: str,
    rec: LadderRecord,
) -> None:
    """Audit-only SESSION upsert (D-04). Never read by the proxy.

    Uses merge (PK-based upsert) so it works on both Postgres and the SQLite test harness.
    """
    if session_factory is None:
        return
    from datetime import UTC, datetime

    from ..incidents.models import SessionRow

    last = datetime.fromtimestamp(rec.last_signal_at, UTC) if rec.last_signal_at else None
    changed = datetime.fromtimestamp(rec.changed_at, UTC) if rec.changed_at else None
    async with session_factory() as session:
        await session.merge(
            SessionRow(
                session_key=session_key,
                ladder_state=rec.state.value,
                current_score=rec.score,
                last_signal_at=last,
                state_changed_at=changed,
            )
        )
        await session.commit()


async def revoke_session(
    redis: Redis,
    session_key: str,
    *,
    jti: str | None,
    now_ts: float,
    score: int = 0,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """Enter REVOKE (D-08): denylist the jti and reset the ladder to OBSERVE/0 so a re-login
    is throttled but functional. Writes a REVOKE audit row. Also used by the enforcement
    path for a persistent BLOCKed attacker (D-14)."""
    if jti is not None:
        await denylist.add(redis, jti)
        # Track which jti(s) belong to this session so an analyst unblock (T13) can remove
        # exactly this session's entries from denylist:jti (PRD §12.1).
        await redis.sadd(f"revoked_jti:{session_key}", jti)
        await redis.expire(f"revoked_jti:{session_key}", 3600)
    prior = await read_ladder(redis, session_key)
    reset = LadderRecord(
        state=LadderState.OBSERVE,
        score=0,
        last_signal_at=now_ts,
        changed_at=now_ts,
        signals_5m=0,
    )
    await write_ladder(redis, session_key, reset)
    await redis.delete(f"blocked_attempts:{session_key}")  # D-14 counter
    audit = replace(prior, state=LadderState.REVOKE, score=score or prior.score, changed_at=now_ts)
    await _upsert_session(session_factory, session_key, audit)


async def apply_signals(
    redis: Redis,
    session_key: str,
    *,
    score: int,
    categories: Iterable[str],
    now_ts: float,
    divisor: int,
    jti: str | None = None,
    challenge_passed: bool = False,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> LadderState:
    """Apply a request's signals: update signals_5m, escalate, persist, return the enforced
    state. On REVOKE, denylist the jti and reset the ladder to OBSERVE/0 (D-08)."""
    rec = await read_ladder(redis, session_key)
    # 5-minute window reset for the history counter
    if rec.last_signal_at and now_ts - rec.last_signal_at > 300 / divisor:
        rec.signals_5m = 0
    rec.signals_5m += 1

    current = rec.state
    new_state = escalate(
        current,
        score=score,
        signals_5m=rec.signals_5m,
        categories=categories,
        challenge_passed=challenge_passed,
    )

    if new_state == LadderState.REVOKE:
        await revoke_session(
            redis,
            session_key,
            jti=jti,
            now_ts=now_ts,
            score=score,
            session_factory=session_factory,
        )
        return LadderState.REVOKE

    rec.score = score
    rec.last_signal_at = now_ts
    if new_state != current:
        rec.changed_at = now_ts
    rec.state = new_state
    await write_ladder(redis, session_key, rec)
    await _upsert_session(session_factory, session_key, rec)
    return new_state


async def apply_decay(
    redis: Redis,
    session_key: str,
    *,
    now_ts: float,
    divisor: int,
    session_factory: async_sessionmaker[AsyncSession] | None = None,
) -> LadderState:
    """Decay the session one rung if it has been quiet long enough."""
    rec = await read_ladder(redis, session_key)
    elapsed = now_ts - rec.last_signal_at if rec.last_signal_at else float("inf")
    new_state = decay(rec.state, elapsed, divisor)
    if new_state != rec.state:
        rec.state = new_state
        rec.changed_at = now_ts
        await write_ladder(redis, session_key, rec)
        await _upsert_session(session_factory, session_key, rec)
    return new_state
