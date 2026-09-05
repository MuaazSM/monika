"""Structural view of a Signal for the scorer.

Scoring sits BELOW detection in the module layering (CLAUDE.md rule 9), so it may not
import `detection.signal`. It only reads a signal's category/severity/evidence, so it
depends on this read-only Protocol instead — `detection.signal.Signal` satisfies it
structurally, keeping scoring pure and dependency-free.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class SignalLike(Protocol):
    @property
    def category(self) -> str: ...

    @property
    def severity(self) -> int: ...

    @property
    def evidence(self) -> Mapping[str, Any]: ...
