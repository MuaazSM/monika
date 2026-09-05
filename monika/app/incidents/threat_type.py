"""Derive the incident threat_type from a request's signals (DECISIONS.md D-02).

Pure and engine-computed — no model input, no free-text. `incidents` sits below detection
in the layering (CLAUDE.md rule 9), so this reads signals through a local structural
protocol rather than importing detection.signal.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from typing import Any, Protocol


class ThreatType(enum.StrEnum):
    BOLA_ENUMERATION = "BOLA_ENUMERATION"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    SQL_INJECTION = "SQL_INJECTION"
    DATA_EXPOSURE = "DATA_EXPOSURE"
    FUNCTION_LEVEL_AUTH = "FUNCTION_LEVEL_AUTH"
    RATE_ABUSE = "RATE_ABUSE"


class SignalLike(Protocol):
    @property
    def category(self) -> str: ...

    @property
    def severity(self) -> int: ...

    @property
    def evidence(self) -> Mapping[str, Any]: ...


# Deterministic tie-break when two categories share the top severity.
_PRECEDENCE = ["auth", "payload", "exposure", "enum", "rate"]


def _dominant_category(signals: Sequence[SignalLike]) -> str:
    """The category with the highest severity; ties broken by _PRECEDENCE."""
    best_by_cat: dict[str, int] = {}
    for s in signals:
        best_by_cat[s.category] = max(best_by_cat.get(s.category, 0), s.severity)
    return max(
        best_by_cat,
        key=lambda c: (best_by_cat[c], -_PRECEDENCE.index(c) if c in _PRECEDENCE else -99),
    )


def derive_threat_type(signals: Sequence[SignalLike]) -> ThreatType:
    """Map a signal set to a ThreatType (D-02)."""
    cats = {s.category for s in signals}
    is_admin_auth = any(
        s.category == "auth" and s.evidence.get("admin_only") is True for s in signals
    )
    # A D3 credential-stuffing signal is a "rate" category signal carrying failures_60s.
    is_stuffing = any(s.category == "rate" and "failures_60s" in s.evidence for s in signals)

    # Correlation signatures win regardless of severity.
    if "auth" in cats and "enum" in cats:
        return ThreatType.BOLA_ENUMERATION
    if "rate" in cats and is_stuffing:
        return ThreatType.CREDENTIAL_STUFFING
    # D-15: a function-level-auth signal is the primary threat on an admin endpoint, even
    # when a bulk-exposure signal co-fires (the dump is a consequence of the broken FLA).
    # This must win over the highest-severity fallback (exposure 85 > auth 70).
    if is_admin_auth:
        return ThreatType.FUNCTION_LEVEL_AUTH

    # Otherwise the highest-severity category decides (ties per _PRECEDENCE).
    dominant = _dominant_category(signals)
    if dominant == "auth":  # non-admin auth (admin handled above) -> BOLA
        return ThreatType.BOLA_ENUMERATION
    if dominant == "enum":
        return ThreatType.BOLA_ENUMERATION
    if dominant == "payload":
        return ThreatType.SQL_INJECTION
    if dominant == "exposure":
        return ThreatType.DATA_EXPOSURE
    return ThreatType.RATE_ABUSE  # rate alone, non-stuffing
