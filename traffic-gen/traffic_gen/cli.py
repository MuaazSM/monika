"""CLI: python -m traffic_gen <scenario>  (benign | idor | stuffing | sqli | scrape | admin)."""

from __future__ import annotations

import argparse
import asyncio

from . import benign
from .scenarios import admin, idor, scrape, sqli, stuffing

_ATTACKS = {
    "idor": idor.run,
    "stuffing": stuffing.run,
    "sqli": sqli.run,
    "scrape": scrape.run,
    "admin": admin.run,
}


def main() -> int:
    parser = argparse.ArgumentParser(prog="traffic_gen")
    parser.add_argument("scenario", choices=["benign", *_ATTACKS])
    parser.add_argument(
        "--duration", type=int, default=300, help="benign duration in seconds (default 300)"
    )
    args = parser.parse_args()

    if args.scenario == "benign":
        return asyncio.run(benign.run(args.duration))
    return asyncio.run(_ATTACKS[args.scenario]())


if __name__ == "__main__":
    raise SystemExit(main())
