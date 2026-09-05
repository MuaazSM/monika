"""Upstream forwarding.

One httpx.AsyncClient is created in the app lifespan and reused for every request — never
per-request (connection pooling matters for p95). Hop-by-hop headers are stripped in both
directions per RFC 7230 §6.1.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

# RFC 7230 §6.1 hop-by-hop headers — must not be forwarded end to end.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass(slots=True)
class ForwardResult:
    """Upstream response plus the measured round-trip time."""

    status: int
    headers: dict[str, str]
    body: bytes
    latency_ms: float


def create_client(upstream_url: str) -> httpx.AsyncClient:
    """Build the process-wide client. Redirects are NOT followed — the proxy is transparent."""
    return httpx.AsyncClient(base_url=upstream_url, timeout=30.0, follow_redirects=False)


def _strip_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop hop-by-hop headers plus host/content-length (httpx recomputes them)."""
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in ("host", "content-length"):
            continue
        out[k] = v
    return out


def _strip_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Drop hop-by-hop and framing headers; Starlette re-sets content-length."""
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in ("content-length", "content-encoding"):
            continue
        out[k] = v
    return out


async def forward_request(
    client: httpx.AsyncClient,
    *,
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    body: bytes,
) -> ForwardResult:
    """Forward one request upstream and return status, headers, body bytes, latency_ms."""
    url = path if not query else f"{path}?{query}"
    started = time.perf_counter()
    resp = await client.request(method, url, headers=_strip_request_headers(headers), content=body)
    latency_ms = (time.perf_counter() - started) * 1000.0
    return ForwardResult(
        status=resp.status_code,
        headers=_strip_response_headers(resp.headers),
        body=resp.content,
        latency_ms=round(latency_ms, 3),
    )
