"""Ladder tests (PRD §8.1, §13.1, DECISIONS.md D-01/D-08)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fakeredis import aioredis
from freezegun import freeze_time

from app.policy import denylist
from app.policy.ladder import (
    DECAY_SECONDS,
    TRANSITIONS,
    LadderState,
    TriggerContext,
    apply_signals,
    band_floor,
    decay,
    escalate,
    read_ladder,
)

S = LadderState


# ---- §8.1 table: iterate every row --------------------------------------------------


def test_transitions_cover_the_8_1_table() -> None:
    edges = {(t.from_state, t.to_state, t.kind) for t in TRANSITIONS}
    assert edges == {
        (S.NORMAL, S.OBSERVE, "escalate"),
        (S.OBSERVE, S.RATE_LIMIT, "escalate"),
        (S.RATE_LIMIT, S.CHALLENGE, "escalate"),
        (S.CHALLENGE, S.BLOCK, "escalate"),
        (S.BLOCK, S.REVOKE, "escalate"),
        (S.OBSERVE, S.NORMAL, "decay"),
        (S.RATE_LIMIT, S.OBSERVE, "decay"),
        (S.CHALLENGE, S.RATE_LIMIT, "decay"),
        (S.BLOCK, S.CHALLENGE, "decay"),
    }


def test_every_transition_fires_on_max_context_and_not_on_empty() -> None:
    all_on = TriggerContext(
        score=100,
        signals_5m=3,
        categories=frozenset({"auth", "exposure"}),
        challenge_passed=True,
        elapsed_seconds=10**9,
        divisor=1,
    )
    all_off = TriggerContext()
    for t in TRANSITIONS:
        assert t.trigger(all_on) is True, f"{t.from_state}->{t.to_state} should fire"
        assert t.trigger(all_off) is False, f"{t.from_state}->{t.to_state} should not fire"
        assert t.enforcement  # every row carries an enforcement note


# ---- D-01 escalation ----------------------------------------------------------------


def test_band_floors() -> None:
    assert band_floor(29) == S.NORMAL
    assert band_floor(30) == S.OBSERVE
    assert band_floor(60) == S.RATE_LIMIT
    assert band_floor(80) == S.CHALLENGE
    assert band_floor(90) == S.BLOCK
    assert band_floor(100) == S.BLOCK


def test_score_100_from_normal_lands_on_block_in_one_step() -> None:
    assert escalate(S.NORMAL, score=100, signals_5m=1, categories={"auth"}) == S.BLOCK


def test_prd_13_1_escalation_sequence() -> None:
    cats = {"auth", "enum", "rate"}
    s1 = escalate(S.NORMAL, score=71, signals_5m=1, categories=cats)
    assert s1 == S.RATE_LIMIT
    s2 = escalate(s1, score=88, signals_5m=2, categories=cats)
    assert s2 == S.CHALLENGE
    s3 = escalate(s2, score=100, signals_5m=3, categories=cats)
    assert s3 == S.BLOCK  # not REVOKE: REVOKE only from BLOCK
    s4 = escalate(s3, score=85, signals_5m=4, categories={"auth"})
    assert s4 == S.REVOKE  # auth signal while BLOCK


def test_revoke_only_from_block() -> None:
    # score 100 from CHALLENGE goes to BLOCK, never straight to REVOKE
    assert escalate(S.CHALLENGE, score=100, signals_5m=1, categories={"auth"}) == S.BLOCK
    # auth signal below BLOCK does not revoke
    assert escalate(S.RATE_LIMIT, score=50, signals_5m=1, categories={"auth"}) != S.REVOKE


def test_signal_count_floor_applies() -> None:
    # 2nd signal in 5 min -> at least RATE_LIMIT even with a low score
    assert escalate(S.OBSERVE, score=0, signals_5m=2, categories={"enum"}) == S.RATE_LIMIT


def test_d13_single_category_caps_at_rate_limit() -> None:
    # D-13: a lone category (even at the 3rd-signal CHALLENGE floor) throttles, not challenges,
    # so a single-vector sweep keeps forwarding and can correlate.
    assert escalate(S.OBSERVE, score=0, signals_5m=3, categories={"enum"}) == S.RATE_LIMIT
    # a lone auth signal (85) throttles instead of jumping to CHALLENGE
    assert escalate(S.NORMAL, score=85, signals_5m=1, categories={"auth"}) == S.RATE_LIMIT


def test_d13_correlation_reaches_block() -> None:
    # two distinct categories with a correlated score is not capped -> full escalation
    assert escalate(S.RATE_LIMIT, score=95, signals_5m=5, categories={"auth", "enum"}) == S.BLOCK


def test_d13_severe_single_category_still_escalates() -> None:
    # a single category at score >= 90 is NOT capped (preserves D-01 "100 -> BLOCK")
    assert escalate(S.NORMAL, score=100, signals_5m=1, categories={"payload"}) == S.BLOCK


def test_never_downgrades() -> None:
    assert escalate(S.CHALLENGE, score=0, signals_5m=0, categories=[]) == S.CHALLENGE


# ---- decay timing (freezegun, one second either side of each boundary) ---------------


@pytest.mark.parametrize(
    ("state", "seconds", "lower"),
    [
        (S.OBSERVE, 300, S.NORMAL),
        (S.RATE_LIMIT, 600, S.OBSERVE),
        (S.CHALLENGE, 600, S.RATE_LIMIT),
        (S.BLOCK, 1800, S.CHALLENGE),
    ],
)
def test_decay_boundaries(state, seconds, lower) -> None:
    last = datetime(2026, 9, 5, 12, 0, 0, tzinfo=UTC)
    # one second before the boundary: no decay
    with freeze_time(last + timedelta(seconds=seconds - 1)):
        now = datetime.now(UTC)
        assert decay(state, (now - last).total_seconds(), divisor=1) == state
    # exactly at the boundary: one rung down
    with freeze_time(last + timedelta(seconds=seconds)):
        now = datetime.now(UTC)
        assert decay(state, (now - last).total_seconds(), divisor=1) == lower


def test_decay_matches_8_1_timings() -> None:
    assert DECAY_SECONDS[S.OBSERVE] == (300, S.NORMAL)
    assert DECAY_SECONDS[S.RATE_LIMIT] == (600, S.OBSERVE)
    assert DECAY_SECONDS[S.CHALLENGE] == (600, S.RATE_LIMIT)
    assert DECAY_SECONDS[S.BLOCK] == (1800, S.CHALLENGE)


def test_decay_honours_divisor() -> None:
    # with divisor 10, OBSERVE decays after 30s not 300s
    assert decay(S.OBSERVE, 29, divisor=10) == S.OBSERVE
    assert decay(S.OBSERVE, 30, divisor=10) == S.NORMAL


def test_normal_and_revoke_do_not_decay() -> None:
    assert decay(S.NORMAL, 10**9, divisor=1) == S.NORMAL
    assert decay(S.REVOKE, 10**9, divisor=1) == S.REVOKE


# ---- persistence + D-08 revoke reset ------------------------------------------------


@pytest.fixture
async def redis():
    r = aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


async def test_apply_signals_persists_state(redis) -> None:
    state = await apply_signals(
        redis, "742", score=71, categories={"auth", "enum"}, now_ts=1000.0, divisor=1
    )
    assert state == S.RATE_LIMIT
    rec = await read_ladder(redis, "742")
    assert rec.state == S.RATE_LIMIT
    assert rec.score == 71
    assert rec.signals_5m == 1


async def test_revoke_denylists_jti_and_resets_ladder(redis) -> None:
    # drive to BLOCK first
    await redis.hset(
        "ladder:742",
        mapping={
            "state": "BLOCK",
            "score": 90,
            "last_signal_at": 1000.0,
            "changed_at": 1000.0,
            "signals_5m": 3,
        },
    )
    state = await apply_signals(
        redis, "742", score=100, categories={"auth"}, now_ts=1001.0, divisor=1, jti="jti-xyz"
    )
    assert state == S.REVOKE
    # D-08: jti denylisted...
    assert await denylist.contains(redis, "jti-xyz") is True
    # ...and the ladder reset to OBSERVE/0 (re-login starts throttled but functional)
    rec = await read_ladder(redis, "742")
    assert rec.state == S.OBSERVE
    assert rec.score == 0
    assert rec.signals_5m == 0
