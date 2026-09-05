"""Simulator control-plane routes (PRD §10.1). The dashboard Simulator screen calls these."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .scenarios import SCENARIOS

router = APIRouter(prefix="/_monika", tags=["simulator"])


class SimulateRequest(BaseModel):
    scenario: str


class SimulateRun(BaseModel):
    run_id: str
    scenario: str
    status: str


@router.post("/simulate", response_model=SimulateRun, status_code=202)
async def simulate(body: SimulateRequest, request: Request) -> SimulateRun:
    """Start one scenario as a background task; return immediately with a run id.
    Refuses to run two scenarios concurrently (409)."""
    if body.scenario not in SCENARIOS:
        raise HTTPException(status_code=400, detail=f"unknown scenario: {body.scenario}")
    try:
        run = request.app.state.simulator.start(body.scenario)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return SimulateRun(run_id=run.run_id, scenario=run.scenario, status=run.status)


@router.get("/simulate/{run_id}", response_model=SimulateRun)
async def simulate_status(run_id: str, request: Request) -> SimulateRun:
    run = request.app.state.simulator.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return SimulateRun(run_id=run.run_id, scenario=run.scenario, status=run.status)
