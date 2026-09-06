"""Endpoints control-plane route (PRD §10.1, §13.1 risk map).

GET /_monika/endpoints returns every configured route with its baseline snapshot
(display columns, D-03) and a risk_level derived from the incidents observed on it.
Read-only: this reflects state, it never changes it. The risk_level drives the §13.1
"risk map" (e.g. /api/users/{id} red, /api/products amber, others green).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request

from .models import EndpointOut, EndpointUpdateIn
from .service import list_endpoints, update_endpoint

router = APIRouter(prefix="/_monika", tags=["endpoints"])


@router.get("/endpoints", response_model=list[EndpointOut])
async def get_endpoints(request: Request) -> list[EndpointOut]:
    return await list_endpoints(request.app.state.session_factory, now=datetime.now(UTC))


@router.put("/endpoints/{id}", response_model=EndpointOut)
async def put_endpoint(id: UUID, body: EndpointUpdateIn, request: Request) -> EndpointOut:
    """Edit owner_field / sensitive_fields / auth_required (PRD §10.1). Takes effect on the
    live matcher immediately, so re-running a scenario against this endpoint changes
    detection, not just the display row (Implementation-Frontend.md Phase 5)."""
    result = await update_endpoint(
        request.app.state.session_factory,
        request.app.state.endpoints,
        id,
        body,
        now=datetime.now(UTC),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="endpoint not found")
    return result
