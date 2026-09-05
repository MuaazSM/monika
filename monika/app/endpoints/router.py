"""Endpoints control-plane route (PRD §10.1, §13.1 risk map).

GET /_monika/endpoints returns every configured route with its baseline snapshot
(display columns, D-03) and a risk_level derived from the incidents observed on it.
Read-only: this reflects state, it never changes it. The risk_level drives the §13.1
"risk map" (e.g. /api/users/{id} red, /api/products amber, others green).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request

from .models import EndpointOut
from .service import list_endpoints

router = APIRouter(prefix="/_monika", tags=["endpoints"])


@router.get("/endpoints", response_model=list[EndpointOut])
async def get_endpoints(request: Request) -> list[EndpointOut]:
    return await list_endpoints(request.app.state.session_factory, now=datetime.now(UTC))
