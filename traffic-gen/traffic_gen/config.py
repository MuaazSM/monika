"""Traffic-gen configuration. Traffic goes through the Monika PROXY, never the demo API."""

from __future__ import annotations

import os

MONIKA_URL = os.environ.get("MONIKA_URL", "http://monika:8000")

# Benign cohort — seeded users with their (non-weak, non-attacker) passwords.
BENIGN_USERS: list[tuple[int, str]] = [
    (703, "pw-703-secret"),
    (711, "pw-711-secret"),
    (720, "pw-720-secret"),
]

# Demo attacker (DECISIONS.md D-09).
ATTACKER_ID = 742
ATTACKER_PASSWORD = "hunter2"
