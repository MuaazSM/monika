"""Confidence tests (PRD §7.4)."""

from __future__ import annotations

from uuid import uuid4

from app.detection.signal import Signal
from app.scoring.confidence import confidence
from app.scoring.state import SessionState


def _sig(category: str, severity: int, evidence=None) -> Signal:
    return Signal(
        category=category,  # type: ignore[arg-type]
        severity=severity,
        evidence=evidence or {"k": "v"},
        request_id="r1",
        endpoint_id=uuid4(),
        session_key="742",
    )


def test_prd_7_3_case_computes_110_clamped_to_99() -> None:
    # 3 categories + 3 prior + a z_score >= 5:
    #   40 + 15*3 + 5*min(3,4) + 10 = 40 + 45 + 15 + 10 = 110 -> clamped to 99.
    # NOTE: confidence saturates at >= 3 categories (40 + 45 = 85, plus the prior/z terms
    # push past 99). This is expected, not a bug — high-correlation incidents read as
    # near-certain by design.
    signals = [_sig("auth", 85), _sig("enum", 60), _sig("rate", 55, {"z_score": 5.1})]
    assert confidence(signals, SessionState(signals_last_5m=3)) == 99


def test_no_signals_is_base_40() -> None:
    assert confidence([], SessionState(signals_last_5m=0)) == 40


def test_high_z_adds_10() -> None:
    base = confidence([_sig("auth", 50)], SessionState(signals_last_5m=0))
    withz = confidence([_sig("rate", 50, {"z_score": 5.0})], SessionState(signals_last_5m=0))
    assert withz - base == 10


def test_z_below_5_does_not_add() -> None:
    withz = confidence([_sig("rate", 50, {"z_score": 4.9})], SessionState(signals_last_5m=0))
    assert withz == 40 + 15  # one category, no z bonus


def test_prior_signals_capped_at_4() -> None:
    at4 = confidence([_sig("auth", 50)], SessionState(signals_last_5m=4))
    at100 = confidence([_sig("auth", 50)], SessionState(signals_last_5m=100))
    assert at4 == at100  # prior term saturates at 4
