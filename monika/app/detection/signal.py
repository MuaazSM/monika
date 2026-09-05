"""The Signal contract (CLAUDE.md §7, PRD §6.1).

Every detector emits Signals. Per CLAUDE.md rule 5, a Signal without populated evidence is
a bug — so an empty `evidence` dict is rejected at construction time.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, field_validator


class Signal(BaseModel):
    category: Literal["auth", "enum", "rate", "payload", "exposure"]
    severity: int  # 0-100
    evidence: dict[str, Any]
    request_id: str
    endpoint_id: UUID | None
    session_key: str  # jwt.sub if authenticated else f"ip:{ip}"

    @field_validator("evidence")
    @classmethod
    def _evidence_must_be_populated(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Rule 5: a Signal without populated evidence is a bug — reject it."""
        if not v:
            raise ValueError("Signal.evidence must be non-empty (CLAUDE.md rule 5)")
        return v
