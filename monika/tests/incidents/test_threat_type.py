"""Table-driven threat_type derivation (DECISIONS.md D-02)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.incidents.threat_type import ThreatType, derive_threat_type


@dataclass
class Sig:
    category: str
    severity: int
    evidence: dict[str, Any] = field(default_factory=dict)


T = ThreatType


@pytest.mark.parametrize(
    ("signals", "expected"),
    [
        # single categories
        ([Sig("auth", 70, {"jwt_sub": 742})], T.BOLA_ENUMERATION),  # auth alone, not admin
        ([Sig("auth", 70, {"admin_only": True})], T.FUNCTION_LEVEL_AUTH),  # auth alone, admin
        ([Sig("enum", 50)], T.BOLA_ENUMERATION),
        ([Sig("rate", 40, {"z_score": 3.0})], T.RATE_ABUSE),  # rate anomaly
        ([Sig("rate", 75, {"failures_60s": 8})], T.CREDENTIAL_STUFFING),  # rate + login
        ([Sig("payload", 60)], T.SQL_INJECTION),
        ([Sig("exposure", 70)], T.DATA_EXPOSURE),
        # correlation signatures
        ([Sig("auth", 85, {"jwt_sub": 1}), Sig("enum", 60)], T.BOLA_ENUMERATION),
        (
            [Sig("auth", 85, {"jwt_sub": 1}), Sig("enum", 60), Sig("rate", 55, {"z_score": 5.1})],
            T.BOLA_ENUMERATION,
        ),  # §7.3 IDOR sweep
        (
            [Sig("rate", 75, {"failures_60s": 9}), Sig("rate", 50, {"z_score": 4.0})],
            T.CREDENTIAL_STUFFING,
        ),  # stuffing + anomaly both rate
        # mixed sets, highest severity wins
        ([Sig("rate", 40, {"z_score": 3.0}), Sig("exposure", 85)], T.DATA_EXPOSURE),
        ([Sig("payload", 80), Sig("exposure", 70)], T.SQL_INJECTION),
        ([Sig("auth", 85, {"jwt_sub": 1}), Sig("exposure", 70)], T.BOLA_ENUMERATION),
        ([Sig("auth", 70, {"admin_only": True}), Sig("exposure", 60)], T.FUNCTION_LEVEL_AUTH),
        # D-15: FLA wins even when a higher-severity bulk exposure co-fires (admin scenario)
        ([Sig("auth", 70, {"admin_only": True}), Sig("exposure", 85)], T.FUNCTION_LEVEL_AUTH),
    ],
)
def test_threat_type_mapping(signals, expected) -> None:
    assert derive_threat_type(signals) == expected
