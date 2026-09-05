"""SQL-injection scenario (PRD §13.2): GET /api/search with tautology and UNION SELECT
variants. Expect D4 injection. threat_type SQL_INJECTION, min score 60."""

from __future__ import annotations

import asyncio

from ..client import LabeledClient
from ..config import MONIKA_URL

LABEL = "attack:sqli"
PAYLOADS = [
    "' OR '1'='1",
    (
        "' UNION SELECT id,name,description,category,price,cost_price,supplier_margin "
        "FROM demo.products --"
    ),
    "zzz' UNION SELECT id,username,ssn,email,0,0,0 FROM demo.users --",
    "1' OR '1'='1' --",
]


async def run() -> int:
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()
        for payload in PAYLOADS * 2:
            await client.get("/api/search", params={"q": payload})
            await asyncio.sleep(0.3)
        print(f"sqli complete: {len(PAYLOADS) * 2} injection attempts")
    return 0
