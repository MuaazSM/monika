"""Anthropic async client — the ONLY module in the codebase allowed to import the SDK
(CLAUDE.md rule 1; enforced by `make lint-arch`)."""

from __future__ import annotations

from typing import Any, cast

import anthropic

from ..settings import Settings
from .job import ExplainerJob
from .prompt import SYSTEM_PROMPT, build_user_message

MAX_TOKENS = 300
TEMPERATURE = 0.2
TIMEOUT_SECONDS = 8.0
MAX_RETRIES = 1


class ExplainerClient:
    """Thin wrapper: one Anthropic call per incident, prose out."""

    def __init__(self, api_key: str, model: str) -> None:
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, timeout=TIMEOUT_SECONDS, max_retries=MAX_RETRIES
        )
        self._model = model

    async def explain(self, job: ExplainerJob) -> str:
        """Call the model and return its text. Raises on API error/timeout (worker handles)."""
        # The SDK's overloaded create() confuses mypy on the kwargs form; the call is valid.
        msg = await self._client.messages.create(  # type: ignore[call-overload]
            model=self._model,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            system=SYSTEM_PROMPT,
            messages=cast("Any", [{"role": "user", "content": build_user_message(job)}]),
        )
        return "".join(block.text for block in msg.content if block.type == "text")

    async def aclose(self) -> None:
        await self._client.close()


def create_client(settings: Settings) -> ExplainerClient | None:
    """Return a client, or None when the explainer is disabled / has no API key (no-op)."""
    if not settings.explainer_enabled or not settings.anthropic_api_key:
        return None
    return ExplainerClient(settings.anthropic_api_key, settings.anthropic_model)
