#!/usr/bin/env python3
"""
reportability.py — Decide whether a finding is worth reporting.

Pure-Python implementation of ``reportability_agent`` (no LLM, no network). It
suggests the next agent but NEVER invokes it. Writes one row per evaluated
finding to data/reportability.csv.

Usage:
    python scripts/reportability.py --finding 42
    python scripts/reportability.py --program acme --all-open
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core import policy as policy_mod  # noqa: E402
from core import reportability as rep_mod  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402

OPEN_STATUSES = {"new", "triaged", "needs-info", "reported"}


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--finding", help="Evaluate a single finding by id.")
    g.add_argument("--all-open", action="store_true", help="Evaluate all open findings.")
    p.add_argument("--program", help="Program handle (required with --all-open).")
    return p.parse_args()


def _load_policy(cfg, store: Store, program: str) -> Optional[Dict[str, Any]]:
    snapshot = cfg.path("scope") / f"{program}.policy.json"
    if snapshot.exists():
        try:
            return json.loads(snapshot.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    row = store.get_policy(program)
    return policy_mod.load_policy_row(row) if row else None


def _evaluate_one(cfg, store, log, finding, all_findings, reports) -> Dict[str, Any]:
    program = finding.get("program", "")
    scopes = store.get_scopes(program)
    policy = _load_policy(cfg, store, program)
    verdict = rep_mod.evaluate(finding, scopes, policy, reports, findings=all_findings)
    store.upsert_reportability(
        verdict["finding_id"], verdict=verdict["verdict"], reason=verdict["reason"],
        priority=verdict["priority"], policy_quote=verdict["policy_quote"],
        next_agent=verdict["next_agent"],
    )
    log.info("reportability evaluated", finding=verdict["finding_id"],
             verdict=verdict["verdict"], priority=verdict["priority"])
    quote = f' quote="{verdict["policy_quote"]}"' if verdict["policy_quote"] else ""
    print(f"REPORTABILITY finding={verdict['finding_id']} verdict={verdict['verdict']} "
          f"priority={verdict['priority'] or '-'} next={verdict['next_agent'] or '-'}{quote}")
    return verdict


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    store = Store()
    log = Logger(agent="reportability_agent")

    all_findings = store.csv.read_all("findings")
    reports = store.list_reports()

    targets: List[Dict[str, Any]]
    if args.all_open:
        if not args.program:
            print("ERROR: --all-open requires --program <handle>.", file=sys.stderr)
            return 1
        targets = [f for f in all_findings
                   if f.get("program") == args.program and f.get("status") in OPEN_STATUSES]
        if not targets:
            print(f"No open findings for program '{args.program}'.")
            return 0
    else:
        finding = next((f for f in all_findings if f.get("id") == str(args.finding)), None)
        if not finding:
            print(f"ERROR: finding '{args.finding}' not found.", file=sys.stderr)
            return 1
        targets = [finding]

    for finding in targets:
        _evaluate_one(cfg, store, log, finding, all_findings, reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
