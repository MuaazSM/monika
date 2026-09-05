"""Function-level-auth scenario (PRD §13.2, DECISIONS.md D-10): a non-admin token hitting
GET /api/admin/users x3. Expect D1 function-level auth. threat_type FUNCTION_LEVEL_AUTH,
min score 70."""

from __future__ import annotations

from ..client import LabeledClient
from ..config import ATTACKER_ID, ATTACKER_PASSWORD, MONIKA_URL

LABEL = "attack:admin"


async def run() -> int:
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()
        token = await client.login(f"user{ATTACKER_ID}", ATTACKER_PASSWORD)  # non-admin 742
        if token is None:
            print("admin: attacker could not authenticate")
            return 1
        for _ in range(3):
            await client.get("/api/admin/users", token=token)
        print("admin complete: 3 non-admin hits on /api/admin/users")
    return 0
