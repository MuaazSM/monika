"""Signal contract: evidence must be non-empty (CLAUDE.md rule 5)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.detection.signal import Signal


def test_empty_evidence_raises() -> None:
    with pytest.raises(ValidationError):
        Signal(
            category="auth",
            severity=70,
            evidence={},  # empty -> rule 5 violation
            request_id="r1",
            endpoint_id=uuid4(),
            session_key="742",
        )


def test_populated_evidence_ok() -> None:
    sig = Signal(
        category="auth",
        severity=70,
        evidence={"reason": "no ownership check", "object_id": "701"},
        request_id="r1",
        endpoint_id=None,
        session_key="742",
    )
    assert sig.evidence["object_id"] == "701"
    assert sig.endpoint_id is None
