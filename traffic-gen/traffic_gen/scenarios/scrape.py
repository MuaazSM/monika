"""Data-scrape scenario (PRD §13.2): GET /api/products?page=1..50 at 5 rps. Expect D4
exposure (cost_price) + D3 rate. threat_type DATA_EXPOSURE, min score 70."""

from __future__ import annotations

import asyncio

from ..client import LabeledClient
from ..config import MONIKA_URL

LABEL = "attack:scrape"
PAGES = 50
RPS = 5.0


async def run() -> int:
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()
        for page in range(1, PAGES + 1):
            await client.get("/api/products", params={"page": page})
            await asyncio.sleep(1.0 / RPS)
        print(f"scrape complete: {PAGES} pages at {RPS} rps")
    return 0
