"""Learning phase (PRD §6.3): drive ~3 minutes of benign traffic through the Monika proxy
across every configured endpoint, then assert every endpoint has n >= 30 baseline samples
and print "learning phase complete".

Traffic goes through the PROXY (MONIKA_URL), not the demo API directly, so it flows through
the same middleware path that records baselines — the numbers the detectors will read are
the numbers this produced.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

import httpx
import yaml
from redis.asyncio import Redis

MONIKA_URL = os.environ.get("MONIKA_URL", "http://monika:8000")
REDIS_URL = os.environ.get("MONIKA_REDIS_URL", "redis://redis:6379/0")
CONFIG = os.environ.get("ENDPOINTS_CONFIG", "config/endpoints.yaml")
DURATION_S = int(os.environ.get("SEED_DURATION_S", "180"))  # 3 minutes
MIN_SAMPLES = 30

# Fixed namespace — must match app.endpoints.models.ENDPOINT_NAMESPACE.
ENDPOINT_NAMESPACE = uuid.UUID("6d6f6e69-6b61-0000-0000-656e64706f69")

# A few benign demo users (700..749 seeded; 700/715/730 have weak pw, 742 is the attacker).
BENIGN_USERS = [(703, "pw-703-secret"), (711, "pw-711-secret"), (720, "pw-720-secret")]


def endpoint_id(method: str, path_pattern: str) -> uuid.UUID:
    return uuid.uuid5(ENDPOINT_NAMESPACE, f"{method.upper()} {path_pattern}")


def load_config(path: str) -> tuple[list[dict], list[str]]:
    data = yaml.safe_load(Path(path).read_text())
    eps = data.get("endpoints", [])
    ids = [str(endpoint_id(e["method"], e["path_pattern"])) for e in eps]
    return eps, ids


async def _login(client: httpx.AsyncClient, uid: int, password: str) -> str | None:
    r = await client.post("/api/login", json={"username": f"user{uid}", "password": password})
    if r.status_code == 200:
        return str(r.json()["access_token"])
    return None


async def _benign_round(client: httpx.AsyncClient, token: str, uid: int) -> None:
    """One benign user behaving normally: reads own data, browses products, searches."""
    auth = {"authorization": f"Bearer {token}", "x-monika-label": "benign"}
    await client.get(f"/api/users/{uid}", headers=auth)
    await client.get(f"/api/users/{uid}/orders", headers=auth)
    await client.get("/api/products?page=1", headers={"x-monika-label": "benign"})
    await client.get("/api/search?q=Product 1", headers={"x-monika-label": "benign"})


async def run() -> int:
    eps, _ = load_config(CONFIG)
    print(f"learning phase: {len(eps)} endpoints, target {DURATION_S}s of benign traffic")

    async with httpx.AsyncClient(base_url=MONIKA_URL, timeout=10.0) as client:
        # wait for the proxy to be up
        for _ in range(60):
            try:
                if (await client.get("/_monika/health")).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1)

        # smoke-test that at least one benign user can authenticate
        if not await _login(client, *BENIGN_USERS[0]):
            print("ERROR: benign users cannot authenticate", file=sys.stderr)
            return 1

        deadline = time.monotonic() + DURATION_S
        rounds = 0
        while time.monotonic() < deadline:
            # Re-auth each round (benign token refresh) so /api/login also accrues samples.
            for uid, pw in BENIGN_USERS:
                tok = await _login(client, uid, pw)
                if tok:
                    await _benign_round(client, tok, uid)
            # NOTE: /api/admin/users is deliberately NOT exercised. It returns a bulk user
            # dump that (correctly) trips D4's scrape-exposure rule (DECISIONS.md D-12), so
            # there is no such thing as a "benign" read of it to baseline.
            rounds += 1
            # ~1 round/sec keeps rpm realistic and reaches n>=30 within 3 minutes
            await asyncio.sleep(1.0)
        print(f"benign traffic done: {rounds} rounds")

    # assert readiness directly against Redis (source of truth, D-03).
    # admin_only endpoints (D-12: unbaselineable bulk-exposure routes) are excluded.
    redis: Redis = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        ok = True
        for ep in eps:
            eid = str(endpoint_id(ep["method"], ep["path_pattern"]))
            if ep.get("admin_only"):
                print(f"  endpoint {eid} ({ep['path_pattern']}): skipped (admin_only, D-12)")
                continue
            raw = await redis.hgetall(f"baseline:{eid}:rpm")
            n = int(raw.get("n", 0))
            print(f"  endpoint {eid}: n={n}")
            if n < MIN_SAMPLES:
                ok = False
    finally:
        await redis.aclose()

    if not ok:
        print("ERROR: some endpoints have < 30 samples", file=sys.stderr)
        return 1
    print("learning phase complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
