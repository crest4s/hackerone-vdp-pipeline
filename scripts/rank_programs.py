#!/usr/bin/env python3
"""
rank_programs.py — Rank HackerOne programs by attractiveness TODAY.

Pure-Python implementation of ``program_selector_agent`` (no LLM, no network).
Reads history from ``data/*.csv`` + ``config/scoring.yaml`` and writes a Markdown
ranking to ``workspace/plans/programs_ranking_<YYYYMMDD>.md``.

Only ``enabled: true`` programs (per ``config/programs.yaml``, the authoritative
flag) are ever ranked.

Usage:
    python scripts/rank_programs.py
    python scripts/rank_programs.py --top 5
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from core import config as cfg_mod  # noqa: E402
from core import scoring  # noqa: E402
from core import policy as policy_mod  # noqa: E402
from core.csvstore import utc_now  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--top", type=int, default=3, help="How many programs to explain in detail.")
    p.add_argument("--out", help="Override the output Markdown path.")
    return p.parse_args()


def load_scoring_cfg(cfg) -> dict:
    path = cfg_mod.PROJECT_ROOT / "config" / "scoring.yaml"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    store = Store()
    log = Logger(agent="program_selector_agent")

    programs = store.list_programs()
    # `enabled` is resolved from config/programs.yaml (source of truth), so a
    # program is only ever ranked when it is genuinely authorised.
    for prog in programs:
        prog["enabled"] = cfg.is_enabled(prog.get("handle", ""))
    disabled = [p for p in programs if not p["enabled"]]

    reports = store.list_reports()
    findings = store.csv.read_all("findings")
    sessions = store.csv.read_all("sessions")
    scopes = store.get_scopes()
    policies = [policy_mod.load_policy_row(r) for r in store.list_policies()]
    scoring_cfg = load_scoring_cfg(cfg)

    ranked = scoring.score_programs(
        programs, reports, findings, sessions, scopes, scoring_cfg,
        policies=policies, today=datetime.now(timezone.utc),
    )

    md = scoring.render_ranking_md(
        ranked, top_n=args.top, generated_at=utc_now(), disabled=disabled,
    )

    plans_dir = cfg_mod.PROJECT_ROOT / "workspace" / "plans"
    plans_dir.mkdir(parents=True, exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    out = Path(args.out) if args.out else plans_dir / f"programs_ranking_{day}.md"
    out.write_text(md, encoding="utf-8")

    best = ranked[0] if ranked else None
    log.info("programs ranked", ranked=len(ranked), disabled=len(disabled),
             best=best["handle"] if best else "")
    if best:
        print(f"SELECT top={args.top} best={best['handle']} score={best['score']} ranking={out}")
    else:
        print(f"SELECT top={args.top} best=<none: no enabled programs> ranking={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
