"""Credential-stuffing scenario (PRD §13.2): 40 POST /api/login using 20 usernames from one
IP within 40s. Expect D3's stuffing rule (>=8 failed 401s OR >=5 distinct usernames in 60s).
threat_type CREDENTIAL_STUFFING, min score 75."""

from __future__ import annotations

import asyncio

from ..client import LabeledClient
from ..config import MONIKA_URL

LABEL = "attack:stuffing"
USERNAMES = [f"user{700 + i}" for i in range(20)]
ATTEMPTS = 40


async def run() -> int:
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()
        for i in range(ATTEMPTS):
            await client.post(
                "/api/login",
                json={"username": USERNAMES[i % len(USERNAMES)], "password": "wrong-password"},
            )
            await asyncio.sleep(1.0)  # ~40 attempts over 40s
        print(f"stuffing complete: {ATTEMPTS} logins, {len(USERNAMES)} usernames")
    return 0
