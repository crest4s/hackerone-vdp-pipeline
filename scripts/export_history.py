#!/usr/bin/env python3
"""
export_history.py — Consolidated snapshot of all CSV history.

Copies every CSV in data/ into a timestamped directory under
workspace/reports/history/<timestamp>/ for backup or diffing, and can also
emit a per-program Markdown summary.

Usage:
    python scripts/export_history.py
    python scripts/export_history.py --markdown
    python scripts/export_history.py --markdown --program acme
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core.store import Store  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--markdown", action="store_true", help="Also write a Markdown summary per program.")
    p.add_argument("--program", help="Limit the Markdown summary to one program.")
    return p.parse_args()


def _copy_csvs(data_dir: Path, dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for csv_file in sorted(data_dir.glob("*.csv")):
        shutil.copy2(csv_file, dest / csv_file.name)
        n += 1
    return n


def _markdown_summary(store: Store, dest: Path, only_program: str | None) -> list[Path]:
    programs = store.list_programs()
    if only_program:
        programs = [p for p in programs if p.get("handle") == only_program]
    written = []
    for p in programs:
        handle = p.get("handle", "unknown")
        findings = store.list_findings(program=handle)
        lines = [
            f"# History snapshot — {p.get('name', handle)} (`{handle}`)",
            "",
            f"- State: {p.get('state','')}",
            f"- Last synced: {p.get('last_synced_at','')}",
            f"- Findings on record: {len(findings)}",
            "",
            "## Findings",
            "",
            "| id | title | severity | status | asset | created |",
            "|----|-------|----------|--------|-------|---------|",
        ]
        for f in findings:
            lines.append(
                f"| {f.get('id','')} | {f.get('title','')} | {f.get('severity','')} "
                f"| {f.get('status','')} | {f.get('asset','')} | {f.get('created_at','')} |"
            )
        out = dest / f"{handle}.md"
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(out)
    return written


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    data_dir = cfg.path("data")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = cfg.path("reports") / "history" / ts

    n = _copy_csvs(data_dir, dest)
    print(f"Copied {n} CSV file(s) -> {dest}")

    if args.markdown:
        md = _markdown_summary(Store(), dest, args.program)
        print(f"Wrote {len(md)} Markdown summary file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
