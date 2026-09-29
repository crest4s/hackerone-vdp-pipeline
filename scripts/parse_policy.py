#!/usr/bin/env python3
"""
parse_policy.py — Parse a program's policy into an actionable structure.

Pure-Python implementation of ``policy_parser_agent`` (no LLM, no network).
Reads the ``policy_md`` of ``data/programs.csv`` plus the textual "Out of Scope"
of the synced structured scope, and writes:

    workspace/scope/<handle>.policy.json
    workspace/scope/<handle>.policy.md
    a row in data/policies.csv

Usage:
    python scripts/parse_policy.py --program acme
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core import policy as policy_mod  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--program", required=True, help="Program handle.")
    return p.parse_args()


def _out_of_scope_texts(scope_dir: Path, handle: str) -> List[str]:
    """Pull the textual 'Out of Scope' from the synced structured-scope JSON."""
    snapshot = scope_dir / f"{handle}.json"
    if not snapshot.exists():
        return []
    try:
        data = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("data", data.get("scopes", []))
    texts: List[str] = []
    for s in data or []:
        attrs = s.get("attributes", s)
        eligible = attrs.get("eligible_for_submission")
        if isinstance(eligible, str):
            eligible = eligible.strip().lower() in ("true", "1", "yes")
        if eligible is False:  # explicitly out of scope
            ident = attrs.get("asset_identifier") or attrs.get("asset") or ""
            instr = attrs.get("instruction") or ""
            line = f"- {ident} {instr}".strip()
            if line != "-":
                texts.append(line)
    return texts


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    store = Store()
    log = Logger(agent="policy_parser_agent")
    scope_dir = cfg.path("scope")

    prog = store.get_program(args.program)
    if not prog:
        print(f"ERROR: program '{args.program}' not found in data/programs.csv "
              f"(run h1_sync first).", file=sys.stderr)
        return 1

    policy_md = prog.get("policy_md", "") or ""
    oos = _out_of_scope_texts(scope_dir, args.program)
    if not policy_md and not oos:
        log.warning("no policy text to parse", program=args.program)
        print(f"WARNING: no policy_md and no out-of-scope text for '{args.program}'. "
              f"Nothing to parse; marking needs_manual_review.")

    parsed = policy_mod.parse_policy(args.program, policy_md, out_of_scope_texts=oos)

    scope_dir.mkdir(parents=True, exist_ok=True)
    json_path = scope_dir / f"{args.program}.policy.json"
    parsed["source_json_path"] = str(json_path)
    json_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")

    md_path = scope_dir / f"{args.program}.policy.md"
    md_path.write_text(policy_mod.render_policy_md(parsed), encoding="utf-8")

    row = policy_mod.policy_to_csv_row(parsed)
    row["source_json_path"] = str(json_path)
    store.upsert_policy(args.program, **{k: v for k, v in row.items() if k != "program"})

    log.info("policy parsed", program=args.program,
             sections=len(parsed["sections_found"]),
             excluded=len(parsed["excluded_vuln_classes"]),
             needs_manual_review=parsed["needs_manual_review"])
    floor = (parsed.get("severity_floor") or {}).get("value", "") or "n/d"
    print(f"POLICY program={args.program} sections={len(parsed['sections_found'])} "
          f"excluded={len(parsed['excluded_vuln_classes'])} floor={floor} "
          f"manual_review={parsed['needs_manual_review']} json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
