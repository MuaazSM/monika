"""Output guard (defence in depth for rule 1).

The model never sees the score or confidence, and its output is validated: any response
that states a confidence/score number, or recommends block/unblock in its Next step, is
rejected and nulled. Evidence numbers (e.g. "6 IDs") are allowed — only score/confidence
framing and block/unblock recommendations are rejected.
"""

from __future__ import annotations

import re

_SCORE_NUMBER = re.compile(r"(?i)\b(confidence|score|rating|risk)\b\W{0,4}\d")
_BLOCK_WORD = re.compile(r"(?i)\b(un)?block")

NEXT_STEP_MARKER = "Next step:"


def split_explanation(text: str) -> tuple[str, str | None]:
    """Split into (two-sentence explanation, next-step action)."""
    idx = text.find(NEXT_STEP_MARKER)
    if idx == -1:
        return text.strip(), None
    return text[:idx].strip(), text[idx + len(NEXT_STEP_MARKER) :].strip() or None


def guard_output(text: str | None) -> str | None:
    """Return the cleaned prose, or None if the response violates the rule-1 constraints."""
    if not text or not text.strip():
        return None
    if _SCORE_NUMBER.search(text):  # e.g. "confidence: 87", "risk 95"
        return None
    _, next_step = split_explanation(text)
    if next_step and _BLOCK_WORD.search(next_step):  # recommending block/unblock
        return None
    return text.strip()
