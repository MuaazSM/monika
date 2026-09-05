"""Round-trip: proxy forwards to a stub upstream, relays the response, and writes exactly
one REQUEST_LOG row with the right fields; a body is forwarded byte-identically."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.incidents.models import RequestLog

from .conftest import make_token


async def _rows(session_factory) -> list[RequestLog]:
    async with session_factory() as s:
        return list((await s.execute(select(RequestLog))).scalars())


async def test_get_roundtrip_and_request_log(client, sqlite_session_factory) -> None:
    resp = await client.get("/api/products?page=2")
    assert resp.status_code == 200
    echoed = resp.json()
    assert echoed["method"] == "GET"
    assert echoed["path"] == "/api/products"
    assert echoed["query"] == {"page": "2"}

    rows = await _rows(sqlite_session_factory)
    assert len(rows) == 1
    row = rows[0]
    assert row.method == "GET"
    assert row.path == "/api/products"
    assert row.status_code == 200
    assert row.resp_bytes > 0
    assert row.latency_ms is not None and row.latency_ms >= 0
    assert row.action_applied == "allow"
    assert row.session_key.startswith("ip:")  # unauthenticated
    assert row.label is None


async def test_authenticated_session_key_and_label(client, sqlite_session_factory) -> None:
    token = make_token(742, "test-secret")
    resp = await client.get(
        "/api/users/701",
        headers={"authorization": f"Bearer {token}", "x-monika-label": "attack"},
    )
    assert resp.status_code == 200
    (row,) = await _rows(sqlite_session_factory)
    assert row.session_key == "742"
    assert row.label == "attack"


async def test_body_forwarded_byte_identically(client, sqlite_session_factory) -> None:
    payload = {"username": "user742", "password": "hunter2", "nested": [1, 2, {"x": "é"}]}
    raw = json.dumps(payload)
    resp = await client.post(
        "/api/login", content=raw, headers={"content-type": "application/json"}
    )
    assert resp.status_code == 200
    echoed = resp.json()
    # The upstream echoes exactly what it received; must equal what we sent, byte for byte.
    assert echoed["body_text"] == raw
    assert echoed["body_sha_len"] == len(raw.encode("utf-8"))
