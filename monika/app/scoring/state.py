"""SessionState — the scoring/confidence input that isn't a Signal.

Lives in `scoring` (not `policy`) so scoring never imports upward: policy imports this.
`current_state` is typed `str` here to avoid importing the policy ladder enum; the ladder
StrEnum (T7) is a str subclass and assigns cleanly.
"""

from __future__ import annotations

from pydantic import BaseModel


class SessionState(BaseModel):
    signals_last_5m: int = 0
    current_state: str = "NORMAL"
    current_score: int = 0
