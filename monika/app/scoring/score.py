"""Risk score (PRD §7.1). Pure: no I/O, no Redis, no clock, no logging.

The score is the maximum category severity plus a bounded correlation bonus plus a bounded
session-history term — NOT an additive sum (a sum double-counts one attack that trips
several detectors). Body copied verbatim from PRD §7.1 / CLAUDE.md rule 2.
"""

from __future__ import annotations

from collections.abc import Sequence

from .protocols import SignalLike
from .state import SessionState

_CORR_BONUS = {1: 0, 2: 10, 3: 18, 4: 25, 5: 25}


def score(signals: Sequence[SignalLike], session: SessionState) -> int:
    if not signals:
        return 0
    by_cat = {
        s.category: max(x.severity for x in signals if x.category == s.category) for s in signals
    }
    base = max(by_cat.values())
    independent = len(by_cat)  # distinct categories this request
    corr_bonus = _CORR_BONUS[independent]
    hist = min(10, 2 * session.signals_last_5m)  # prior evidence in this session
    return min(100, base + corr_bonus + hist)
