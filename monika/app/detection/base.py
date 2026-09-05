"""The detector interface and the RequestContext it operates on (CLAUDE.md §7).

RequestContext is defined here (the boundary type detectors receive). `detection.context`
re-exports it plus `derive_session_key` for the proxy, which already imports from there.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict
from redis.asyncio import Redis

from ..endpoints.models import EndpointConfig
from .signal import Signal


class JWTClaims(BaseModel):
    """The three claims the proxy extracts. Business validity is a detector concern."""

    sub: int
    jti: str
    role: str


class ResponseContext(BaseModel):
    """Upstream response as seen by the detectors: status, bytes, body_json | None."""

    status: int
    bytes: int
    body_json: Any = None


class RequestContext(BaseModel):
    """Everything a detector needs about one request+response pair (CLAUDE.md §7)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    request_id: str
    method: str
    path: str
    path_params: dict[str, str]
    query: dict[str, str]
    headers: dict[str, str]
    body_json: Any = None
    jwt: JWTClaims | None
    ip: str
    # Resolved by the endpoint matcher; None for unconfigured routes.
    endpoint: EndpointConfig | None = None
    response: ResponseContext
    started_at: datetime
    latency_ms: float
    label: str | None = None


class Detector(Protocol):
    name: str

    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]: ...
