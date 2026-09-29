#!/usr/bin/env python3
"""
dashboard.py — Rich CLI overview of the pipeline's current state.

Shows: programs, open findings by severity, reports by state, accumulated
bounties, and most recent activity. READ-ONLY.

Usage:
    python scripts/dashboard.py
    python scripts/dashboard.py --program acme
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.store import Store  # noqa: E402

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

SEV_ORDER = ["critical", "high", "medium", "low", "info", ""]
OPEN_STATUSES = {"new", "triaged", "needs-info", "reported"}


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--program", help="Filter the whole view to one program.")
    return p.parse_args()


def _fallback_render(store: Store, program):
    print("== Programs =="); 
    for p in store.list_programs():
        print(f"  {p['handle']:24s} {p.get('state',''):14s} bounty={p.get('bounty','')}")
    fnd = store.list_findings(program=program)
    sev = Counter(f.get("severity", "") for f in fnd if f.get("status") in OPEN_STATUSES)
    print("== Open findings by severity ==")
    for s in SEV_ORDER:
        if sev.get(s):
            print(f"  {s or 'unrated':10s} {sev[s]}")
    rep = Counter(r.get("state", "") for r in store.list_reports())
    print("== Reports by state ==")
    for st, n in rep.items():
        print(f"  {st or 'unknown':12s} {n}")
    total = 0.0
    for r in store.list_reports():
        try:
            total += float(r.get("bounty_amount") or 0)
        except ValueError:
            pass
    print(f"== Accumulated bounties: {total:.2f} ==")


def _rich_render(store: Store, program):
    console = Console()

    # Programs
    t = Table(title="Programs", box=box.SIMPLE_HEAVY, expand=False)
    for col in ("handle", "name", "state", "bounty", "last_synced_at"):
        t.add_column(col)
    for p in store.list_programs():
        if program and p.get("handle") != program:
            continue
        t.add_row(p.get("handle",""), p.get("name",""), p.get("state",""),
                  p.get("bounty",""), p.get("last_synced_at",""))
    console.print(t)

    # Open findings by severity
    findings = store.list_findings(program=program)
    sev = Counter(f.get("severity","") for f in findings if f.get("status") in OPEN_STATUSES)
    ft = Table(title="Open findings by severity", box=box.SIMPLE_HEAVY)
    ft.add_column("severity"); ft.add_column("open", justify="right")
    colour = {"critical":"bold red","high":"red","medium":"yellow","low":"green"}
    for s in SEV_ORDER:
        if sev.get(s):
            label = s or "unrated"
            ft.add_row(f"[{colour.get(s,'white')}]{label}[/]", str(sev[s]))
    console.print(ft)

    # Reports by state
    rt = Table(title="Reports by state", box=box.SIMPLE_HEAVY)
    rt.add_column("state"); rt.add_column("count", justify="right")
    rep = Counter(r.get("state","") for r in store.list_reports())
    for st, n in sorted(rep.items()):
        rt.add_row(st or "unknown", str(n))
    console.print(rt)

    # Bounties + last activity
    total = 0.0
    for r in store.list_reports():
        try:
            total += float(r.get("bounty_amount") or 0)
        except ValueError:
            pass
    events = store.csv.read_all("events")
    last = events[-5:] if events else []
    console.print(f"[bold green]Accumulated bounties:[/] {total:.2f}")
    at = Table(title="Recent activity (last 5 events)", box=box.SIMPLE_HEAVY)
    for col in ("ts","agent","level","message"):
        at.add_column(col)
    for e in last:
        at.add_row(e.get("ts",""), e.get("agent",""), e.get("level",""), e.get("message",""))
    console.print(at)


def main() -> int:
    args = _parse_args()
    store = Store()
    if _RICH:
        _rich_render(store, args.program)
    else:
        print("(rich not installed — plain output)\n")
        _fallback_render(store, args.program)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
