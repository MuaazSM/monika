"""Dump the demo API's OpenAPI schema to openapi.json (consumed by Tier 3 T19)."""

from __future__ import annotations

import json
from pathlib import Path

from app.main import create_app


def main() -> None:
    schema = create_app().openapi()
    out = Path(__file__).parent / "openapi.json"
    out.write_text(json.dumps(schema, indent=2) + "\n")
    print(f"wrote {out} ({len(schema.get('paths', {}))} paths)")


if __name__ == "__main__":
    main()
