"""Endpoint configuration models (PRD §6.2, DECISIONS.md D-10)."""

from __future__ import annotations

import re
import uuid
from functools import cached_property

from pydantic import BaseModel, ConfigDict

# Fixed namespace so uuid5(method, path_pattern) is stable across restarts (D-10 intent).
ENDPOINT_NAMESPACE = uuid.UUID("6d6f6e69-6b61-0000-0000-656e64706f69")


class EndpointConfig(BaseModel):
    """One configured route. endpoint_id is derived, not stored in yaml."""

    model_config = ConfigDict(frozen=True)

    method: str
    path_pattern: str
    id_param: str | None = None
    owner_field: str | None = None
    auth_required: bool = False
    sensitive_fields: tuple[str, ...] = ()
    admin_only: bool = False

    @cached_property
    def endpoint_id(self) -> uuid.UUID:
        """Stable per (method, path_pattern) — survives restarts."""
        return uuid.uuid5(ENDPOINT_NAMESPACE, f"{self.method.upper()} {self.path_pattern}")

    @cached_property
    def _regex(self) -> re.Pattern[str]:
        """Compile the path pattern into a matcher with named groups per {param}."""
        parts = re.split(r"(\{[^}]+\})", self.path_pattern)
        out = []
        for part in parts:
            if part.startswith("{") and part.endswith("}"):
                name = part[1:-1]
                out.append(rf"(?P<{name}>[^/]+)")
            else:
                out.append(re.escape(part))
        return re.compile("^" + "".join(out) + "$")

    def match_path(self, path: str) -> dict[str, str] | None:
        """Return extracted path params if `path` matches, else None."""
        m = self._regex.match(path)
        return m.groupdict() if m else None
