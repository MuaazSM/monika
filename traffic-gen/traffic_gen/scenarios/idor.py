"""IDOR sweep scenario (PRD §13.2).

User 742 (the demo attacker, DECISIONS.md D-09) logs in, then GETs /api/users/{id} for
700..730 at 3 rps. Expected: D1 (BOLA) + D2 (enumeration) + D3 (rate) -> a
BOLA_ENUMERATION incident with score >= 90, and the ladder escalating to BLOCK/REVOKE.
"""

from __future__ import annotations

import asyncio

from ..client import LabeledClient
from ..config import ATTACKER_ID, ATTACKER_PASSWORD, MONIKA_URL

LABEL = "attack:idor"
SWEEP = range(700, 731)  # 700..730
RPS = 3.0


async def run() -> int:
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()
        token = await client.login(f"user{ATTACKER_ID}", ATTACKER_PASSWORD)
        if token is None:
            print("IDOR: attacker could not authenticate")
            return 1

        interval = 1.0 / RPS
        statuses: dict[int, int] = {}
        for object_id in SWEEP:
            resp = await client.get(f"/api/users/{object_id}", token=token)
            statuses[resp.status_code] = statuses.get(resp.status_code, 0) + 1
            await asyncio.sleep(interval)
        print(f"IDOR sweep complete: status counts {statuses}")
    return 0
