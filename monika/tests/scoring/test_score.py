"""Scoring tests (PRD §7.1, §7.3 worked example)."""

from __future__ import annotations

from uuid import uuid4

from app.detection.signal import Signal
from app.scoring.score import score
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


def test_prd_7_3_worked_example_is_exactly_100() -> None:
    # auth 85, enum 60, rate 55; 3 prior signals -> 85 + 18 + 6 = 109 -> capped 100
    signals = [_sig("auth", 85), _sig("enum", 60), _sig("rate", 55, {"z_score": 5.1})]
    session = SessionState(signals_last_5m=3)
    assert score(signals, session) == 100


def test_empty_signals_returns_zero() -> None:
    assert score([], SessionState(signals_last_5m=10)) == 0


def test_single_category_never_exceeds_severity_plus_10() -> None:
    # corr_bonus for 1 category is 0; hist is capped at 10 -> max is severity + 10
    signals = [_sig("auth", 70)]
    assert score(signals, SessionState(signals_last_5m=100)) == 80  # 70 + 0 + 10
    assert score(signals, SessionState(signals_last_5m=0)) == 70


def test_single_category_takes_max_severity() -> None:
    signals = [_sig("auth", 40), _sig("auth", 85), _sig("auth", 60)]
    assert score(signals, SessionState(signals_last_5m=0)) == 85


def test_four_categories_add_25() -> None:
    signals = [_sig("auth", 30), _sig("enum", 20), _sig("rate", 10), _sig("payload", 15)]
    assert score(signals, SessionState(signals_last_5m=0)) == 30 + 25


def test_five_categories_also_add_25() -> None:
    signals = [
        _sig("auth", 30),
        _sig("enum", 20),
        _sig("rate", 10),
        _sig("payload", 15),
        _sig("exposure", 25),
    ]
    assert score(signals, SessionState(signals_last_5m=0)) == 30 + 25


def test_two_categories_add_10() -> None:
    signals = [_sig("auth", 50), _sig("enum", 40)]
    assert score(signals, SessionState(signals_last_5m=0)) == 60
