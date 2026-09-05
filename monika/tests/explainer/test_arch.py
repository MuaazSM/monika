"""Architecture guard (CLAUDE.md rule 1): only app/explainer/ may import the Anthropic SDK.

This mirrors the import-linter `anthropic-isolation` contract (make lint-arch) as a unit
test, so a stray `import anthropic` anywhere else fails the pytest suite too.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"


def _is_anthropic(name: str | None) -> bool:
    return bool(name) and (name == "anthropic" or name.startswith("anthropic."))  # type: ignore[union-attr]


def _imports_anthropic(path: Path) -> bool:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import) and any(_is_anthropic(a.name) for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and _is_anthropic(node.module):
            return True
    return False


def test_only_explainer_imports_anthropic() -> None:
    offenders = [
        str(p.relative_to(APP))
        for p in APP.rglob("*.py")
        if "explainer" not in p.parts and _imports_anthropic(p)
    ]
    assert offenders == [], f"anthropic imported outside explainer/: {offenders}"


def test_explainer_client_does_import_anthropic() -> None:
    # sanity: the isolation is real, not vacuous — the SDK IS used, in exactly one place.
    assert _imports_anthropic(APP / "explainer" / "client.py")
