"""structlog configuration — JSON output with request_id/session_key on every line."""

from __future__ import annotations

import logging

import structlog


def configure_logging() -> None:
    """Configure structlog once for the process (JSON renderer, contextvars merged in)."""
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )
