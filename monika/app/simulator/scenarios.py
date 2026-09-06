"""Attack scenario runners for the Simulator (PRD §13.2).

Each runner drives traffic through Monika's own proxy (self_url) with the X-Monika-Label
header (§10.4), so detection runs exactly as it would for external traffic. Mirrors the
traffic-gen CLI scenarios; kept here because monika cannot import the traffic-gen package.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import httpx

ATTACKER_USER = "user742"
ATTACKER_PASSWORD = "hunter2"
_SQLI = [
    "' OR '1'='1",
    (
        "' UNION SELECT id,name,description,category,price,cost_price,supplier_margin "
        "FROM demo.products --"
    ),
    "zzz' UNION SELECT id,username,ssn,email,0,0,0 FROM demo.users --",
    "1' OR '1'='1' --",
]


async def _login(client: httpx.AsyncClient, label: str, username: str, password: str) -> str | None:
    r = await client.post(
        "/api/login",
        json={"username": username, "password": password},
        headers={"x-monika-label": label},
    )
    return str(r.json()["access_token"]) if r.status_code == 200 else None


async def run_idor(client: httpx.AsyncClient) -> None:
    label = "attack:idor"
    token = await _login(client, label, ATTACKER_USER, ATTACKER_PASSWORD)
    auth = {"x-monika-label": label, "authorization": f"Bearer {token}"}
    for oid in range(700, 731):
        await client.get(f"/api/users/{oid}", headers=auth)
        await asyncio.sleep(1 / 3)


async def run_stuffing(client: httpx.AsyncClient) -> None:
    label = "attack:stuffing"
    for i in range(40):
        await client.post(
            "/api/login",
            json={"username": f"user{700 + (i % 20)}", "password": "wrong-password"},
            headers={"x-monika-label": label},
        )
        await asyncio.sleep(1.0)


async def run_sqli(client: httpx.AsyncClient) -> None:
    label = "attack:sqli"
    for payload in _SQLI * 2:
        await client.get("/api/search", params={"q": payload}, headers={"x-monika-label": label})
        await asyncio.sleep(0.3)


async def run_scrape(client: httpx.AsyncClient) -> None:
    label = "attack:scrape"
    for page in range(1, 51):
        await client.get("/api/products", params={"page": page}, headers={"x-monika-label": label})
        await asyncio.sleep(0.2)


async def run_benign(client: httpx.AsyncClient) -> None:
    """A short benign burst: three users reading their own data + browsing products."""
    for uid, pw in ((703, "pw-703-secret"), (711, "pw-711-secret"), (720, "pw-720-secret")):
        token = await _login(client, "benign", f"user{uid}", pw)
        auth = {"x-monika-label": "benign", "authorization": f"Bearer {token}"}
        for page in range(1, 6):
            await client.get(f"/api/users/{uid}", headers=auth)
            await client.get(f"/api/users/{uid}/orders", headers=auth)
            await client.get("/api/products", params={"page": page}, headers=auth)
            await asyncio.sleep(0.05)


async def run_admin(client: httpx.AsyncClient) -> None:
    label = "attack:admin"
    token = await _login(client, label, ATTACKER_USER, ATTACKER_PASSWORD)
    auth = {"x-monika-label": label, "authorization": f"Bearer {token}"}
    for _ in range(3):
        await client.get("/api/admin/users", headers=auth)


SCENARIOS: dict[str, Callable[[httpx.AsyncClient], Awaitable[None]]] = {
    "idor": run_idor,
    "stuffing": run_stuffing,
    "sqli": run_sqli,
    "scrape": run_scrape,
    "admin": run_admin,
    "benign": run_benign,
}
