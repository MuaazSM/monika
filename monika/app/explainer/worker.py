"""Explainer worker: an asyncio task (NOT Celery, NOT a new process — rule 8) consuming a
Queue of ExplainerJobs fed by the incident service.

Runs AFTER the incident is persisted and the decision enforced (rule 1: the LLM never
decides). On success it writes llm_explanation/llm_next_step and emits incident.explained;
on failure, timeout, or a guard rejection it leaves both null and the UI shows
'Explanation unavailable' (PRD §14.1). The worker does not import `incidents` (it sits
below it in the layering): it writes back via raw SQL and publishes via an injected
callback, keeping the module graph one-way.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import UUID

import structlog
from sqlalchemy import Uuid, bindparam
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..settings import Settings
from .client import ExplainerClient
from .guard import guard_output, split_explanation
from .job import ExplainerJob

logger = structlog.get_logger(__name__)

_FALLBACK_PATH = Path(__file__).parent / "fallback_idor.txt"

PublishExplained = Callable[[UUID], Awaitable[None]]


def _fallback_text() -> str:
    return _FALLBACK_PATH.read_text().strip()


class ExplainerWorker:
    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        client: ExplainerClient | None,
        publish_explained: PublishExplained,
    ) -> None:
        self._settings = settings
        self._sf = session_factory
        self._client = client
        self._publish = publish_explained

    async def _raw_explanation(self, job: ExplainerJob) -> str | None:
        """The model's (or fallback's) raw text, or None if the explainer is a no-op/failed."""
        if not self._settings.explainer_enabled:
            return None
        if self._settings.explainer_fallback:  # demo-day canned explanation
            return _fallback_text()
        if self._client is None:  # empty API key → never call out
            return None
        try:
            return await self._client.explain(job)
        except Exception as exc:
            logger.warning("explainer.failed", incident_id=str(job.incident_id), error=str(exc))
            return None

    async def handle(self, job: ExplainerJob) -> None:
        raw = await self._raw_explanation(job)
        guarded = guard_output(raw)
        if guarded is None:
            if raw is not None:  # produced text but it failed the output guard
                logger.warning("explainer.rejected", incident_id=str(job.incident_id))
            return  # leave llm_explanation / llm_next_step null
        explanation, next_step = split_explanation(guarded)
        async with self._sf() as session:
            # Raw SQL keeps the worker from importing `incidents` (a higher layer). The id
            # bindparam is typed Uuid so it adapts to the dialect (SQLite hex / Postgres uuid).
            stmt = sa_text(
                "UPDATE incident SET llm_explanation = :e, llm_next_step = :n WHERE id = :id"
            ).bindparams(bindparam("id", type_=Uuid()))
            await session.execute(stmt, {"e": explanation, "n": next_step, "id": job.incident_id})
            await session.commit()
        await self._publish(job.incident_id)
        logger.info("explainer.explained", incident_id=str(job.incident_id))


async def run_worker(worker: ExplainerWorker, queue: asyncio.Queue[ExplainerJob]) -> None:
    """Consume jobs forever. One bad job never kills the loop."""
    while True:
        job = await queue.get()
        try:
            await worker.handle(job)
        except Exception:
            logger.exception("explainer.worker_error")
        finally:
            queue.task_done()
