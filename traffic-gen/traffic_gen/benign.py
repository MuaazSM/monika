"""Benign profile (PRD §13.2): 3 users browsing normally at ~1 rps TOTAL.

They log in properly, read only their OWN resources, and page /api/products at a human
rate. This must never produce an incident >= 30 (the Tier 1 acceptance gate), so it is
paced conservatively: one request per second across all three users combined.
"""

from __future__ import annotations

import asyncio

from .client import LabeledClient
from .config import BENIGN_USERS, MONIKA_URL

LABEL = "benign"
RPS_TOTAL = 1.0  # combined across all benign users


async def run(duration_s: int = 300) -> int:
    """Drive benign traffic for `duration_s` seconds. Returns 0."""
    async with LabeledClient(MONIKA_URL, LABEL) as client:
        await client.wait_ready()

        # Each user logs in once and reuses its token; page cursors advance per user.
        tokens: dict[int, str] = {}
        pages: dict[int, int] = {}
        for uid, pw in BENIGN_USERS:
            tok = await client.login(f"user{uid}", pw)
            if tok:
                tokens[uid] = tok
                pages[uid] = 1

        loop = asyncio.get_event_loop()
        deadline = loop.time() + duration_s
        actions = ("profile", "orders", "products")
        step = 0
        interval = len(BENIGN_USERS) / RPS_TOTAL / len(actions)  # ~1s per request total

        while loop.time() < deadline:
            for uid in list(tokens):
                token = tokens[uid]
                action = actions[step % len(actions)]
                if action == "profile":
                    await client.get(f"/api/users/{uid}", token=token)  # own profile
                elif action == "orders":
                    await client.get(f"/api/users/{uid}/orders", token=token)  # own orders
                else:
                    await client.get(f"/api/products?page={pages[uid]}", token=token)
                    pages[uid] += 1
                await asyncio.sleep(interval)
            step += 1
        print(f"benign traffic complete ({duration_s}s)")
    return 0
