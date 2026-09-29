#!/usr/bin/env python3
"""
h1_sync.py — Sync HackerOne programs and structured scopes into local history.

Reads credentials from the environment (H1_USERNAME / H1_API_TOKEN), pulls
programs and their structured scopes, and writes:

    data/programs.csv
    data/scopes.csv
    workspace/scope/<handle>.json   (raw snapshot, audit trail)

This is a READ-ONLY sync. It never submits anything to HackerOne.

Usage:
    python scripts/h1_sync.py --program acme
    python scripts/h1_sync.py --all
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as `python scripts/h1_sync.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--program", help="Sync a single program by handle.")
    g.add_argument("--all", action="store_true", help="Sync all accessible programs.")
    p.add_argument("--dry-network", action="store_true",
                   help="Do not call the API; just show what would be synced.")
    return p.parse_args()


def _write_scope_snapshot(scope_dir: Path, handle: str, scopes) -> Path:
    scope_dir.mkdir(parents=True, exist_ok=True)
    out = scope_dir / f"{handle}.json"
    out.write_text(json.dumps(scopes, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def sync_program(handle: str, client, store: Store, scope_dir: Path, log: Logger,
                 cfg=None) -> dict:
    program = client.get_program(handle)
    attrs = program.get("data", {}).get("attributes", program.get("attributes", {}))
    # `enabled` (from config, the authoritative flag) and `policy` text are
    # persisted so the analyst layer (program_selector / policy_parser) can work
    # straight from data/*.csv without re-reading YAML.
    enabled = cfg.is_enabled(handle) if cfg is not None else None
    store.upsert_program(
        handle=handle,
        name=attrs.get("name", ""),
        state=attrs.get("state", ""),
        bounty=str(attrs.get("offers_bounties", "")),
        enabled=enabled,
        policy_md=attrs.get("policy", "") or "",
    )
    scopes = client.get_structured_scopes(handle)
    _write_scope_snapshot(scope_dir, handle, scopes)

    n_scopes = 0
    for s in scopes:
        sa = s.get("attributes", s)
        asset = sa.get("asset_identifier") or sa.get("asset") or ""
        if not asset:
            continue
        store.upsert_scope(
            program=handle,
            asset=asset,
            asset_type=sa.get("asset_type", ""),
            in_scope=bool(sa.get("eligible_for_submission", True)),
            severity_max=sa.get("max_severity", ""),
            eligible_for_bounty=bool(sa.get("eligible_for_bounty", False)),
            eligible_for_submission=bool(sa.get("eligible_for_submission", True)),
            notes=sa.get("instruction", "") or "",
        )
        n_scopes += 1

    log.info("program synced", program=handle, scopes=n_scopes)
    return {"handle": handle, "scopes": n_scopes}


def main() -> int:
    args = _parse_args()
    cfg = cfg_mod.load()
    store = Store()
    log = Logger(agent="h1_agent")
    scope_dir = cfg.path("scope")

    # Determine target handles.
    handles = []
    if args.program:
        handles = [args.program]

    if args.dry_network:
        print(f"[dry-network] would sync: {handles or 'ALL accessible programs'}")
        return 0

    try:
        from core.h1_api import from_config
        client = from_config(cfg)
    except Exception as exc:  # noqa: BLE001
        log.error("could not build H1 client", error=str(exc))
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.all:
        try:
            handles = []
            for prog in client.list_programs():
                h = prog.get("attributes", {}).get("handle") or prog.get("id")
                if h:
                    handles.append(h)
        except Exception as exc:  # noqa: BLE001
            log.error("failed to list programs", error=str(exc))
            print(f"ERROR listing programs: {exc}", file=sys.stderr)
            return 1

    total = 0
    for h in handles:
        try:
            res = sync_program(h, client, store, scope_dir, log, cfg=cfg)
            print(f"OK  {h:30s} scopes={res['scopes']}")
            total += 1
        except Exception as exc:  # noqa: BLE001
            log.error("program sync failed", program=h, error=str(exc))
            print(f"ERR {h:30s} {exc}", file=sys.stderr)
            continue

    print(f"\nSynced {total}/{len(handles)} program(s). Scope snapshots in {scope_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
