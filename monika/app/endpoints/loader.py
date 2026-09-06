"""Load config/endpoints.yaml into an EndpointRegistry and resolve live requests."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import yaml

from .models import EndpointConfig


class EndpointRegistry:
    """The set of configured endpoints plus the admin allow-list (D-10)."""

    def __init__(self, endpoints: list[EndpointConfig], admin_subs: list[int]) -> None:
        self.endpoints = endpoints
        self.admin_subs = set(admin_subs)
        self._by_method: dict[str, list[EndpointConfig]] = {}
        for ep in endpoints:
            self._by_method.setdefault(ep.method.upper(), []).append(ep)

    def match(self, method: str, path: str) -> tuple[EndpointConfig | None, dict[str, str]]:
        """Resolve a live (method, path) to its config and extracted path params."""
        for ep in self._by_method.get(method.upper(), []):
            params = ep.match_path(path)
            if params is not None:
                return ep, params
        return None, {}

    def update(
        self,
        endpoint_id: UUID,
        *,
        owner_field: str | None,
        sensitive_fields: tuple[str, ...],
        auth_required: bool,
    ) -> EndpointConfig | None:
        """Replace the endpoint's config in place with the given editable fields (PUT
        /_monika/endpoints/{id}, PRD §10.1). EndpointConfig is frozen, so this swaps in a new
        instance — every subsequent `match()` (the very next proxied request) sees the change,
        which is what lets editing sensitive_fields actually change live detection rather than
        only the display row (Implementation-Frontend.md Phase 5)."""
        for i, ep in enumerate(self.endpoints):
            if ep.endpoint_id != endpoint_id:
                continue
            new_ep = ep.model_copy(
                update={
                    "owner_field": owner_field,
                    "sensitive_fields": sensitive_fields,
                    "auth_required": auth_required,
                }
            )
            self.endpoints[i] = new_ep
            bucket = self._by_method[ep.method.upper()]
            bucket[bucket.index(ep)] = new_ep
            return new_ep
        return None


def load_registry(config_path: str | Path) -> EndpointRegistry:
    """Parse the yaml. Raises if the file is missing or malformed."""
    data = yaml.safe_load(Path(config_path).read_text())
    endpoints = [EndpointConfig(**e) for e in data.get("endpoints", [])]
    admin_subs = list(data.get("admin_subs", []))
    return EndpointRegistry(endpoints, admin_subs)
