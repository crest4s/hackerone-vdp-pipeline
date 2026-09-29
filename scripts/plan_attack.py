#!/usr/bin/env python3
"""
plan_attack.py — Build a prioritised attack plan for one in-scope asset.

Pure-Python implementation of ``attack_planner_agent`` (no LLM, no network).
Validates the asset against scope FIRST (hard gate), then filters a checklist by
the parsed policy and orders it by ROI.

Writes:
    workspace/recon/<handle>/<session>/plan_<asset>.md
    a row in data/plans.csv

Usage:
    python scripts/plan_attack.py --program acme --asset app.acme.com
    python scripts/plan_attack.py --program acme --asset api.acme.com --session <id>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core import planner as planner_mod  # noqa: E402
from core import policy as policy_mod  # noqa: E402
from core import scope as scope_mod  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402

ALLOW, ERROR, DENY = 0, 1, 2


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--program", required=True, help="Program handle.")
    p.add_argument("--asset", required=True, help="Asset to plan for (host/url/ip).")
    p.add_argument("--session", help="Session id (a timestamped one is generated if omitted).")
    return p.parse_args()


def _scope_rows(store: Store, cfg, program: str) -> List[Dict[str, Any]]:
    """Prefer scopes.csv (richest); fall back to the JSON snapshot."""
    rows = store.get_scopes(program)
    if rows:
        return rows
    snapshot = cfg.path("scope") / f"{program}.json"
    if snapshot.exists():
        out = []
        for s in scope_mod.load_scope_json(snapshot):
            attrs = s.get("attributes", s)
            out.append({
                "program": program,
                "asset": attrs.get("asset_identifier") or attrs.get("asset") or "",
                "asset_type": attrs.get("asset_type", ""),
                "in_scope": bool(attrs.get("eligible_for_submission", True)),
                "eligible_for_submission": bool(attrs.get("eligible_for_submission", True)),
                "eligible_for_bounty": bool(attrs.get("eligible_for_bounty", False)),
                "severity_max": attrs.get("max_severity", ""),
            })
        return out
    return []


def _load_policy(cfg, store: Store, program: str) -> Optional[Dict[str, Any]]:
    snapshot = cfg.path("scope") / f"{program}.policy.json"
    if snapshot.exists():
        try:
            return json.loads(snapshot.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    row = store.get_policy(program)
    return policy_mod.load_policy_row(row) if row else None


def _is_true(v: Any, default: bool = False) -> bool:
    s = str(v).strip().lower()
    return default if s == "" else s in ("1", "true", "yes", "y")


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    store = Store()
    log = Logger(agent="attack_planner_agent")

    scopes = _scope_rows(store, cfg, args.program)
    if not scopes:
        print(f"PLAN DENY program={args.program} asset={args.asset} "
              f"reason=no scope data (run h1_sync first); deny-by-default", file=sys.stderr)
        return DENY

    # ── HARD GATE: only plan over a scope-validated asset ────────────────
    decision = scope_mod.validate(args.asset, scopes, program=args.program)
    if not decision.allowed:
        log.warning("plan refused: asset out of scope",
                    program=args.program, asset=args.asset, reason=decision.reason)
        print(f"PLAN DENY program={args.program} asset={args.asset} "
              f"reason=\"{decision.reason}\"", file=sys.stderr)
        return DENY

    matched = decision.matched_asset
    srow = next((s for s in scopes if s.get("asset") == matched), {})
    asset_type = srow.get("asset_type", "")
    bounty_eligible = _is_true(srow.get("eligible_for_bounty"), default=False)

    parsed_policy = _load_policy(cfg, store, args.program)
    if parsed_policy is None:
        log.warning("no parsed policy; planning without policy filters",
                    program=args.program)
        print(f"WARNING: no parsed policy for '{args.program}' "
              f"(run parse_policy first). Planning with no exclusions applied.")

    checklist_name = planner_mod.classify_asset(args.asset, asset_type)
    checklist_path = cfg_mod.PROJECT_ROOT / "config" / "checklists" / f"{checklist_name}.md"
    if not checklist_path.exists():
        print(f"ERROR: no checklist for asset type '{checklist_name}' ({checklist_path})",
              file=sys.stderr)
        return ERROR
    checklist_items = planner_mod.load_checklist(checklist_path)

    session_id = args.session or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{args.program}"
    plan = planner_mod.build_plan(
        args.program, args.asset, asset_type, parsed_policy, checklist_items,
        session_id=session_id, bounty_eligible=bounty_eligible,
    )

    out_dir = cfg.path("recon") / args.program / session_id
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_asset = re.sub(r"[^A-Za-z0-9._-]+", "_", args.asset)
    plan_path = out_dir / f"plan_{safe_asset}.md"
    plan_path.write_text(planner_mod.render_plan_md(plan), encoding="utf-8")

    store.create_plan(
        args.program, args.asset, session_id=session_id, priority=plan["priority"],
        checks_count=plan["checks_count"], plan_path=str(plan_path),
    )
    log.info("attack plan built", program=args.program, asset=args.asset,
             checks=plan["checks_count"], priority=plan["priority"])
    print(f"PLAN program={args.program} asset={args.asset} type={plan['asset_type']} "
          f"checks={plan['checks_count']} priority={plan['priority']} plan={plan_path}")
    return ALLOW


if __name__ == "__main__":
    raise SystemExit(main())
