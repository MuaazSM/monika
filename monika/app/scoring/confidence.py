"""Engine-computed confidence (PRD §7.4). Pure, and NEVER sourced from or shown to the LLM
(CLAUDE.md rule 3).

confidence = min(99, 40 + 15*distinct_categories + 5*min(prior_signals_5m, 4)
                      + 10*(1 if any signal has z_score >= 5 else 0))
"""

from __future__ import annotations

from collections.abc import Sequence

from .protocols import SignalLike
from .state import SessionState


def _has_high_z(signals: Sequence[SignalLike]) -> bool:
    for s in signals:
        z = s.evidence.get("z_score")
        if isinstance(z, int | float) and z >= 5:
            return True
    return False


def confidence(signals: Sequence[SignalLike], session: SessionState) -> int:
    distinct_categories = len({s.category for s in signals})
    prior = min(session.signals_last_5m, 4)
    high_z = 10 if _has_high_z(signals) else 0
    return min(99, 40 + 15 * distinct_categories + 5 * prior + high_z)
