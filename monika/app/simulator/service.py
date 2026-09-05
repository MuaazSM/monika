"""Simulator run manager: at most one scenario at a time, run as a background asyncio task
(rule 8 — no new process/queue). A second concurrent request is refused with 409."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

import httpx
import structlog

from ..settings import Settings
from .scenarios import SCENARIOS

logger = structlog.get_logger(__name__)


@dataclass
class SimRun:
    run_id: str
    scenario: str
    status: str  # running | done | failed


@dataclass
class Simulator:
    settings: Settings
    _runs: dict[str, SimRun] = field(default_factory=dict)
    _active: str | None = None  # run_id of the in-flight scenario, if any
    _task: asyncio.Task[None] | None = None  # keep a strong ref so the task isn't GC'd

    def get(self, run_id: str) -> SimRun | None:
        return self._runs.get(run_id)

    def start(self, scenario: str) -> SimRun:
        """Start a scenario in the background. Raises RuntimeError if one is already running."""
        if scenario not in SCENARIOS:
            raise KeyError(scenario)
        if self._active is not None:
            raise RuntimeError("a scenario is already running")
        run = SimRun(run_id=str(uuid.uuid4()), scenario=scenario, status="running")
        self._runs[run.run_id] = run
        self._active = run.run_id
        self._task = asyncio.create_task(self._run(run))
        return run

    async def _run(self, run: SimRun) -> None:
        try:
            async with httpx.AsyncClient(base_url=self.settings.self_url, timeout=15.0) as client:
                await SCENARIOS[run.scenario](client)
            run.status = "done"
        except Exception:
            run.status = "failed"
            logger.exception("simulator.failed", scenario=run.scenario)
        finally:
            self._active = None
