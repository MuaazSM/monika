"""A thin httpx wrapper that FORCES X-Monika-Label on every request (PRD §10.4).

The precision panel is computed from these labels, so an unlabeled request is a bug — this
client makes it impossible to send one.
"""

from __future__ import annotations

from types import TracebackType
from typing import Self

import httpx


class LabeledClient:
    """Wraps httpx.AsyncClient and stamps a fixed X-Monika-Label on every call."""

    def __init__(self, base_url: str, label: str, timeout: float = 10.0) -> None:
        self._label = label
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    def _headers(self, token: str | None, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {"x-monika-label": self._label}
        if token:
            headers["authorization"] = f"Bearer {token}"
        if extra:
            headers.update(extra)
        return headers

    async def get(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
        token: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._client.get(path, params=params, headers=self._headers(token, extra))

    async def post(
        self,
        path: str,
        *,
        json: dict[str, object] | None = None,
        token: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._client.post(path, json=json, headers=self._headers(token, extra))

    async def login(self, username: str, password: str) -> str | None:
        """Log in (labeled) and return the access token, or None."""
        r = await self.post("/api/login", json={"username": username, "password": password})
        if r.status_code == 200:
            return str(r.json()["access_token"])
        return None

    async def wait_ready(self, attempts: int = 60) -> bool:
        for _ in range(attempts):
            try:
                if (await self._client.get("/_monika/health")).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            import asyncio

            await asyncio.sleep(1)
        return False
