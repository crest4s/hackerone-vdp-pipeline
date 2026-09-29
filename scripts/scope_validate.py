#!/usr/bin/env python3
"""
scope_validate.py — Decide whether a target is in scope for a program.

Exit codes (usable as a gate in any other script / shell pipeline):
    0  -> target is IN scope   (allow)
    2  -> target is OUT of scope (deny)
    1  -> error (missing scope data, bad args)

Usage:
    python scripts/scope_validate.py --program acme --target sub.example.com
    python scripts/scope_validate.py --program acme --target https://api.example.com/v1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core import scope as scope_mod  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402

ALLOW, ERROR, DENY = 0, 1, 2


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--program", required=True, help="Program handle.")
    p.add_argument("--target", required=True, help="Host, URL or IP to validate.")
    p.add_argument("--quiet", action="store_true", help="Only set the exit code.")
    return p.parse_args()


def _load_scopes(cfg, program: str):
    """Prefer the raw JSON snapshot; fall back to scopes.csv."""
    snapshot = cfg.path("scope") / f"{program}.json"
    if snapshot.exists():
        return scope_mod.load_scope_json(snapshot)
    # Fall back to CSV history.
    rows = Store().get_scopes(program)
    return [
        {
            "asset": r.get("asset", ""),
            "eligible_for_submission": (r.get("in_scope", "true").lower() == "true"),
            "asset_type": r.get("asset_type", ""),
        }
        for r in rows
    ]


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    log = Logger(agent="scope_agent")

    scopes = _load_scopes(cfg, args.program)
    if not scopes:
        log.warning("no scope data available", program=args.program, target=args.target)
        if not args.quiet:
            print(f"SCOPE DENY target={args.target} program={args.program} "
                  f"reason=no scope data (run h1_sync first); deny-by-default")
        return DENY

    decision = scope_mod.validate(args.target, scopes, program=args.program)
    log.log(
        "scope decision",
        level="info" if decision.allowed else "warning",
        payload={"target": args.target, "program": args.program,
                 "allowed": decision.allowed, "reason": decision.reason,
                 "matched": decision.matched_asset},
    )
    if not args.quiet:
        verb = "ALLOW" if decision.allowed else "DENY"
        print(f"SCOPE {verb} target={args.target} program={args.program} "
              f"matched=\"{decision.matched_asset}\" reason=\"{decision.reason}\"")
    return ALLOW if decision.allowed else DENY


if __name__ == "__main__":
    raise SystemExit(main())
