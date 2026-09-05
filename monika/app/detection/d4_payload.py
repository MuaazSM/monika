"""Detector D4 — Payload / Exposure (PRD §6.7).

Two INDEPENDENT sub-rules in one detector, emitting two DISTINCT Signal categories
(they must stay distinct for the correlation bonus — do not merge them):

  * Injection (category "payload"): a curated, anchored pattern set applied to query param
    values, path segments, and every JSON string in the request body (keys included, so
    NoSQL operator keys like {"$ne": ...} are caught). Severity 60; 80 when the response
    was 200 AND its size exceeds 3x the endpoint's baseline bytes.
  * Exposure (category "exposure"): configured sensitive_fields appearing as KEYS anywhere
    in a 200 response body. Severity 70; 85 when the body is a list of > 20 items.

Patterns are anchored so ordinary prose does not trip them (e.g. the word "select" in a
product description only matches inside a real UNION SELECT).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from redis.asyncio import Redis

from .base import RequestContext
from .baselines import read_bytes
from .context import derive_session_key
from .signal import Signal

EXCERPT_LEN = 40
INJECTION_BASE = 60
INJECTION_ABNORMAL = 80
ABNORMAL_BYTES_FACTOR = 3
EXPOSURE_BASE = 70
EXPOSURE_LIST = 85
EXPOSURE_LIST_THRESHOLD = 20
# D-16: DISTINCT resource signatures (path params + query, e.g. ?page=N) a session reads on
# one sensitive endpoint within a SHORT window. A scrape covers the catalogue fast (all its
# distinct pages in seconds); benign browsing reaches the same pages but spread over minutes,
# so few fall inside the window. Repeated reads of the same page don't count. This separates a
# scrape from benign browsing, which neither raw volume nor cumulative breadth can (benign
# eventually covers a small catalogue too).
EXPOSURE_BREADTH_THRESHOLD = 8
EXPOSURE_BREADTH_WINDOW = 30
EXPOSURE_BREADTH_TTL = 60

# Curated pattern set. Each is anchored to avoid matching benign prose.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # tautology requires OR/AND with EQUAL operands (backref) -> "color or size=large" is safe
    ("sql_tautology", re.compile(r"(?i)\b(?:or|and)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b")),
    ("union_select", re.compile(r"(?i)\bunion\b(?:\s+all)?\s+\bselect\b")),
    # comment terminators only in injection context: /* , or a quote/digit before -- or #
    ("sql_comment", re.compile(r"/\*|['\"\d]\s*(?:--|#)")),
    ("stacked_query", re.compile(r"(?i);\s*(?:drop|select|insert|update|delete|alter|create)\b")),
    ("nosql_operator", re.compile(r"(?i)\$(?:ne|gt|lt|gte|lte|eq|where|regex|in|nin|exists)\b")),
    ("template_command", re.compile(r"\{\{.+?\}\}|\$\(.+?\)|`.+?`")),
]


def _match(value: str) -> str | None:
    """Return the name of the first pattern family that matches, else None."""
    for name, pattern in _PATTERNS:
        if pattern.search(value):
            return name
    return None


def _walk_strings(obj: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield (label, string) for every string in a JSON structure — dict keys and values
    (keys catch operator-style NoSQL injection), recursing into nested objects and arrays."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield f"{path}.{k}", k
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk_strings(item, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _resource_signature(ctx: RequestContext) -> str:
    """A stable id for the specific resource read — path params + query (e.g. page=3)."""
    parts = sorted(ctx.path_params.items()) + sorted(ctx.query.items())
    return "&".join(f"{k}={v}" for k, v in parts)


async def _record_exposure_breadth(
    redis: Redis, session_key: str, endpoint_id: object, signature: str, now_ts: float
) -> int:
    """Record this resource read (ZSET member=signature, score=now) and return how many
    DISTINCT resources the session read on this endpoint within the last window seconds.
    Redis ZSET exposure_pages:{sk}:{eid}."""
    key = f"exposure_pages:{session_key}:{endpoint_id}"
    await redis.zadd(key, {signature: now_ts})
    await redis.zremrangebyscore(key, "-inf", now_ts - EXPOSURE_BREADTH_WINDOW)
    await redis.expire(key, EXPOSURE_BREADTH_TTL)
    return int(await redis.zcard(key))


def _collect_keys(obj: Any) -> set[str]:
    """All dict keys appearing anywhere in the structure (recursing into lists)."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        keys.update(k for k in obj if isinstance(k, str))
        for v in obj.values():
            keys |= _collect_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            keys |= _collect_keys(item)
    return keys


class PayloadDetector:
    """D4. Stateless; baseline bytes come from Redis."""

    name = "d4_payload"

    def _find_injection(self, ctx: RequestContext) -> tuple[str, str, str] | None:
        """First (pattern_name, parameter, value) across query, path, body — else None."""
        # query param values
        for key in sorted(ctx.query):
            value = ctx.query[key]
            name = _match(value)
            if name:
                return name, f"query.{key}", value
        # path segments
        for i, seg in enumerate(s for s in ctx.path.split("/") if s):
            name = _match(seg)
            if name:
                return name, f"path[{i}]", seg
        # request body strings (keys + values)
        for label, value in _walk_strings(ctx.body_json, "body"):
            name = _match(value)
            if name:
                return name, label, value
        return None

    async def run(self, ctx: RequestContext, redis: Redis) -> list[Signal]:
        signals: list[Signal] = []
        session_key = derive_session_key(ctx.jwt, ctx.ip)
        endpoint_id = ctx.endpoint.endpoint_id if ctx.endpoint else None

        # --- injection sub-rule (category "payload") ---
        match = self._find_injection(ctx)
        if match is not None:
            name, parameter, value = match
            severity = INJECTION_BASE
            if ctx.response.status == 200 and endpoint_id is not None:
                bytes_mean, _ = await read_bytes(redis, endpoint_id)
                if bytes_mean > 0 and ctx.response.bytes > ABNORMAL_BYTES_FACTOR * bytes_mean:
                    severity = INJECTION_ABNORMAL
            signals.append(
                Signal(
                    category="payload",
                    severity=severity,
                    evidence={
                        "matched_pattern": name,
                        "parameter": parameter,
                        "value_excerpt": value[:EXCERPT_LEN],
                    },
                    request_id=ctx.request_id,
                    endpoint_id=endpoint_id,
                    session_key=session_key,
                )
            )

        # --- exposure sub-rule (category "exposure") — DECISIONS.md D-12, D-16 ---
        # Excessive data exposure is a SCRAPE, not a single legitimate read. Fires when
        # sensitive fields are present AND EITHER the response is a bulk list (>20 -> 85) or
        # abnormally large vs baseline (>3x -> 70), OR the session has read > 20 DISTINCT
        # resources (pages) of this endpoint (D-16 breadth -> 70). A single/slow read (own
        # profile, benign product paging of a few pages) stays under the breadth floor, so
        # benign browsing produces no incident (Gate 1 criterion 2).
        ep = ctx.endpoint
        if ctx.response.status == 200 and ep is not None and ep.sensitive_fields:
            body = ctx.response.body_json
            present = sorted(set(ep.sensitive_fields) & _collect_keys(body))
            if present and endpoint_id is not None:
                is_list = isinstance(body, list)
                list_length = len(body) if is_list else None
                is_bulk = is_list and len(body) > EXPOSURE_LIST_THRESHOLD
                bytes_mean, _ = await read_bytes(redis, endpoint_id)
                is_oversized = (
                    bytes_mean > 0 and ctx.response.bytes > ABNORMAL_BYTES_FACTOR * bytes_mean
                )
                # D-16: a scrape reads many DISTINCT resources (pages) of a sensitive endpoint.
                breadth = await _record_exposure_breadth(
                    redis,
                    session_key,
                    endpoint_id,
                    _resource_signature(ctx),
                    ctx.started_at.timestamp(),
                )
                is_scrape = breadth > EXPOSURE_BREADTH_THRESHOLD
                if is_bulk or is_oversized or is_scrape:
                    signals.append(
                        Signal(
                            category="exposure",
                            severity=EXPOSURE_LIST if is_bulk else EXPOSURE_BASE,
                            evidence={
                                "sensitive_fields_present": present,
                                "response_bytes": ctx.response.bytes,
                                "list_length": list_length,
                            },
                            request_id=ctx.request_id,
                            endpoint_id=endpoint_id,
                            session_key=session_key,
                        )
                    )

        return signals
