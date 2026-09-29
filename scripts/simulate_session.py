#!/usr/bin/env python3
"""
simulate_session.py — End-to-end dry run of the analyst pipeline (NO network).

Exercises the four new decision engines (program_selector, policy_parser,
attack_planner, reportability) by invoking their Python functions — never an LLM
and never the network — over fictional data, in a fully isolated directory:

    workspace/plans/_simulation/          <- all outputs + temporary CSVs
        csv/                              <- temp data store (real data/*.csv untouched)
        programs_ranking.md
        <handle>.policy.json   (x3)
        <handle>.policy.md     (x3)
        plan_<asset>.md        (x2)
        reportability_report.md

Exit code 0 if everything runs; 1 on any exception (trace in workspace/logs/).

Usage:
    python scripts/simulate_session.py
"""

from __future__ import annotations

import re
import shutil
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import config as cfg_mod  # noqa: E402
from core import planner as planner_mod  # noqa: E402
from core import policy as policy_mod  # noqa: E402
from core import reportability as rep_mod  # noqa: E402
from core import scoring  # noqa: E402
from core.csvstore import CSVStore  # noqa: E402
from core.logger import Logger  # noqa: E402
from core.store import Store, dedup_hash  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
CHECKLIST_DIR = cfg_mod.PROJECT_ROOT / "config" / "checklists"

# Deterministic scoring config for the simulation (independent of the user's
# real config/scoring.yaml so the demo is reproducible).
SCORING_CFG: Dict[str, Any] = {
    "weights": {
        "bounty": 0.25, "triage_speed": 0.15, "scope": 0.15, "competition": 0.10,
        "skill_fit": 0.15, "freshness": 0.10, "saturation": 0.10,
    },
    "skill_set": ["web", "api", "cloud"],
    "saturacion_umbral_dias": 14,
    "competencia_programas": {"acme-cloud": 0.4, "lockdown-bank": 0.6, "newstartup": 0.3},
}


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def _is_true(v: Any, default: bool = True) -> bool:
    s = str(v).strip().lower()
    return default if s == "" else s in ("1", "true", "yes", "y")


# ──────────────────────────────────────────────────────────────────────────
#  Fictional policies (permissive / restrictive / red-flags)
# ──────────────────────────────────────────────────────────────────────────
POLICY_ACME = """
# Rules of Engagement
Both manual and automated testing are welcome against authenticated and
unauthenticated endpoints. Test accounts can be created via the sign-up page.
Please keep your request rate under 20 requests per second. Do not perform
denial of service, and do not run aggressive fuzzing against production.

## In Scope
All *.acme-cloud.com web properties and the public API.

## Out of Scope
- Self-XSS that cannot be used against another user.
- Missing security headers without a documented, demonstrable impact.
- Clickjacking on pages with no sensitive state-changing action.
- Open redirect without a real security impact.

## Rewards
We pay a monetary bounty in USD for the first valid report. Swag is offered for
low-severity issues.

## Reporting Requirements
Provide a proof of concept and clear steps to reproduce. Reports must be in
English and include a CVSS score and a business-impact description.
"""

POLICY_LOCKDOWN = """
LOCKDOWN BANK — SECURITY TESTING POLICY

Rules of Engagement:
Only manual testing is permitted. Automated tools and scanners are not allowed.
You must contact us and get prior approval before testing any asset. Testing is
restricted to the staging environment during business hours.

Prohibited:
Denial of service, brute force, credential stuffing and social engineering are
strictly forbidden. Do not use automated scanning of any kind.

Excluded / Not eligible:
- Missing security headers.
- Clickjacking.
- CSRF on login or logout.
- Reports of low or medium severity are not eligible; minimum severity: high.

Rewards:
Monetary bounty is paid only for high and critical findings on core banking
assets. Recognition is offered otherwise.

Reporting Requirements:
A video proof of concept is required for every submission. Reports in English.
"""

POLICY_NEWSTARTUP = """
# Testing Policy
We welcome manual and automated testing across all of our assets. Authenticated
testing is encouraged; create as many test accounts as you need.

## Out of Scope
- Self-XSS.
- Best-practice / informational reports.

## Rewards
We pay a monetary bounty for any valid security issue, from low to critical.

## Reporting Requirements
Please include steps to reproduce. Any language is fine.
"""


# ──────────────────────────────────────────────────────────────────────────
#  Seed the isolated store
# ──────────────────────────────────────────────────────────────────────────
def seed_store(store: Store) -> None:
    # ── programs (one disabled, to prove it is never ranked) ──────────────
    store.upsert_program("acme-cloud", name="Acme Cloud", state="public_mode",
                         bounty="true", enabled=True, policy_md=POLICY_ACME)
    store.upsert_program("lockdown-bank", name="Lockdown Bank", state="public_mode",
                         bounty="true", enabled=True, policy_md=POLICY_LOCKDOWN)
    store.upsert_program("newstartup", name="New Startup", state="soft_launched",
                         bounty="true", enabled=True, policy_md=POLICY_NEWSTARTUP)
    store.upsert_program("shadow-corp", name="Shadow Corp (disabled)", state="public_mode",
                         bounty="true", enabled=False, policy_md="")

    # ── scopes: wildcards + URLs + IP/CIDR + an explicit out-of-scope ─────
    S = store.upsert_scope
    S("acme-cloud", "*.acme-cloud.com", asset_type="WILDCARD", in_scope=True,
      severity_max="critical", eligible_for_bounty=True, eligible_for_submission=True)
    S("acme-cloud", "api.acme-cloud.com", asset_type="URL", in_scope=True,
      severity_max="critical", eligible_for_bounty=True, eligible_for_submission=True)
    S("acme-cloud", "assets-acme.s3.amazonaws.com", asset_type="URL", in_scope=True,
      severity_max="medium", eligible_for_bounty=False, eligible_for_submission=True)
    S("acme-cloud", "203.0.113.0/24", asset_type="CIDR", in_scope=True,
      severity_max="high", eligible_for_bounty=True, eligible_for_submission=True)
    S("acme-cloud", "legacy.acme-cloud.com", asset_type="URL", in_scope=False,
      severity_max="none", eligible_for_bounty=False, eligible_for_submission=False,
      notes="Decommissioned — explicitly OUT OF SCOPE")
    S("lockdown-bank", "www.lockdown-bank.com", asset_type="URL", in_scope=True,
      severity_max="high", eligible_for_bounty=True, eligible_for_submission=True)
    S("newstartup", "*.newstartup.io", asset_type="WILDCARD", in_scope=True,
      severity_max="high", eligible_for_bounty=True, eligible_for_submission=True)
    S("newstartup", "api.newstartup.io", asset_type="URL", in_scope=True,
      severity_max="high", eligible_for_bounty=True, eligible_for_submission=True)

    # ── findings (id, program, title, severity, cwe, asset, endpoint,
    #             vuln_class, status, created_days_ago) ────────────────────
    findings_seed = [
        # current, open — these are what reportability evaluates.
        (1, "acme-cloud", "IDOR exposes other users' invoices", "high", "CWE-639",
         "app.acme-cloud.com", "https://app.acme-cloud.com/api/invoices/123", "IDOR", "new", 1),
        (2, "acme-cloud", "Missing security headers on dashboard", "low", "CWE-693",
         "app.acme-cloud.com", "https://app.acme-cloud.com/", "Missing security headers", "new", 1),
        (3, "lockdown-bank", "Reflected XSS in search", "medium", "CWE-79",
         "www.lockdown-bank.com", "https://www.lockdown-bank.com/search?q=1", "Reflected XSS", "new", 1),
        (4, "acme-cloud", "SSRF via webhook endpoint", "critical", "CWE-918",
         "api.acme-cloud.com", "https://api.acme-cloud.com/webhook", "SSRF", "new", 0),
        (5, "acme-cloud", "Open redirect on logout", "medium", "CWE-601",
         "legacy.acme-cloud.com", "https://legacy.acme-cloud.com/out?url=x", "Open redirect", "new", 0),
        # historical, resolved — feed bounty/triage history.
        (6, "acme-cloud", "SQL injection (fixed)", "high", "CWE-89",
         "app.acme-cloud.com", "https://app.acme-cloud.com/legacy", "SQL injection", "resolved", 65),
        (7, "acme-cloud", "Auth bypass (fixed)", "high", "CWE-287",
         "api.acme-cloud.com", "https://api.acme-cloud.com/v1/login", "Authentication bypass", "resolved", 40),
        (8, "lockdown-bank", "IDOR (fixed)", "high", "CWE-639",
         "www.lockdown-bank.com", "https://www.lockdown-bank.com/acct/1", "IDOR", "resolved", 100),
        # a prior SUBMITTED SSRF with the SAME dedup as finding #4 → already_reported.
        (9, "acme-cloud", "SSRF via webhook endpoint", "critical", "CWE-918",
         "api.acme-cloud.com", "https://api.acme-cloud.com/webhook", "SSRF", "resolved", 30),
    ]
    for fid, prog, title, sev, cwe, asset, endpoint, vclass, status, days in findings_seed:
        store.csv.upsert("findings", {
            "id": str(fid), "program": prog, "title": title, "severity": sev,
            "cvss_vector": "", "cvss_score": "", "cwe": cwe, "asset": asset,
            "status": status, "dedup_hash": dedup_hash(prog, asset, vclass, endpoint),
            "report_path": "", "created_at": _iso(days), "updated_at": _iso(days),
            "vuln_class": vclass,
        }, key=["id"])

    # ── reports (id, finding_id, submitted_days, triaged_days, state, bounty) ─
    reports_seed = [
        (1, 6, 65, 63, "resolved", "1500"),
        (2, 7, 40, 39, "triaged", "2500"),
        (3, 8, 100, 80, "resolved", "400"),
        (4, 9, 5, 4, "submitted", ""),   # submitted SSRF → finding #4 already_reported
    ]
    for rid, fid, sub, tri, state, bounty in reports_seed:
        store.csv.upsert("reports", {
            "id": str(rid), "finding_id": str(fid), "version": "1",
            "path": f"workspace/reports/sim/{fid}/report.md",
            "submitted_at": _iso(sub), "h1_report_id": f"H1-{rid:04d}",
            "state": state, "triaged_at": _iso(tri), "bounty_amount": bounty,
        }, key=["id"])

    # ── sessions (backdated, drive freshness) ─────────────────────────────
    for sid, prog, days in [(1, "acme-cloud", 3), (2, "lockdown-bank", 22)]:
        store.csv.upsert("sessions", {
            "id": str(sid), "program": prog, "agent": "recon_agent",
            "started_at": _iso(days), "ended_at": _iso(days - 0.1),
            "tools_used": "subfinder,httpx", "stats_json": "{}",
        }, key=["id"])


# ──────────────────────────────────────────────────────────────────────────
#  Simulation driver
# ──────────────────────────────────────────────────────────────────────────
def run(sim_dir: Path, log: Logger) -> Dict[str, Any]:
    csv_dir = sim_dir / "csv"
    if csv_dir.exists():
        shutil.rmtree(csv_dir)
    store = Store(csv=CSVStore(data_dir=csv_dir))
    seed_store(store)
    log.info("simulation seeded", programs=4, findings=9, reports=4)

    programs = store.list_programs()
    reports = store.list_reports()
    findings = store.csv.read_all("findings")
    sessions = store.csv.read_all("sessions")
    scopes = store.get_scopes()

    # Parse the three policies up front (needed to rank the no-history program).
    parsed_policies: Dict[str, Dict[str, Any]] = {}
    for prog in programs:
        handle = prog.get("handle", "")
        md = prog.get("policy_md", "")
        if md:
            parsed_policies[handle] = policy_mod.parse_policy(handle, md)

    outputs: Dict[str, Any] = {}

    # ── Phase -1: program_selector → ranking ──────────────────────────────
    disabled = [p for p in programs if not _is_true(p.get("enabled"), default=False)]
    ranked = scoring.score_programs(
        programs, reports, findings, sessions, scopes, SCORING_CFG,
        policies=list(parsed_policies.values()), today=NOW,
    )
    ranking_md = scoring.render_ranking_md(
        ranked, top_n=3, generated_at=NOW.isoformat(), disabled=disabled, simulation=True,
    )
    (sim_dir / "programs_ranking.md").write_text(ranking_md, encoding="utf-8")
    outputs["ranking"] = ranked
    log.info("ranking done", best=ranked[0]["handle"] if ranked else "")

    # ── Phase 0: policy_parser → structured policy per program ────────────
    for handle, parsed in parsed_policies.items():
        parsed["_SIMULACION"] = True
        json_path = sim_dir / f"{handle}.policy.json"
        parsed["source_json_path"] = str(json_path)
        import json as _json
        json_path.write_text(_json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
        (sim_dir / f"{handle}.policy.md").write_text(
            policy_mod.render_policy_md(parsed, simulation=True), encoding="utf-8")
        row = policy_mod.policy_to_csv_row(parsed)
        store.upsert_policy(handle, **{k: v for k, v in row.items() if k != "program"})
    outputs["policies"] = parsed_policies

    # ── Phase 2: attack_planner → plan for 2 assets of the winner ─────────
    from core import scope as scope_mod
    winner = ranked[0]["handle"]
    winner_scopes = [s for s in scopes if s["program"] == winner and _is_true(s.get("in_scope"))]
    candidate_assets: List[str] = []
    for s in winner_scopes:
        a = s["asset"]
        if a.startswith("*."):
            candidate_assets.append("app." + a[2:])
        elif "/" in a and re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d+$", a):
            continue  # skip CIDR for per-asset web planning
        else:
            candidate_assets.append(a)

    planned: List[Dict[str, Any]] = []
    for asset in candidate_assets:
        if len(planned) >= 2:
            break
        decision = scope_mod.validate(asset, winner_scopes, program=winner)
        if not decision.allowed:
            continue
        srow = next((s for s in winner_scopes if s["asset"] == decision.matched_asset), {})
        plan = planner_mod.build_plan(
            winner, asset, srow.get("asset_type", ""), parsed_policies.get(winner),
            planner_mod.load_checklist(CHECKLIST_DIR / f"{planner_mod.classify_asset(asset, srow.get('asset_type',''))}.md"),
            session_id="SIM-SESSION", bounty_eligible=_is_true(srow.get("eligible_for_bounty"), default=False),
            today=NOW.isoformat(),
        )
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", asset)
        (sim_dir / f"plan_{safe}.md").write_text(
            planner_mod.render_plan_md(plan, simulation=True), encoding="utf-8")
        store.create_plan(winner, asset, session_id="SIM-SESSION",
                          priority=plan["priority"], checks_count=plan["checks_count"],
                          plan_path=str(sim_dir / f"plan_{safe}.md"))
        planned.append(plan)
    outputs["plans"] = planned
    log.info("planning done", assets=[p["asset"] for p in planned])

    # ── Phase 6: reportability → verdict per current open finding ─────────
    open_findings = [f for f in findings if f["id"] in ("1", "2", "3", "4", "5")]
    verdicts: List[Dict[str, Any]] = []
    for f in open_findings:
        prog = f["program"]
        pol = parsed_policies.get(prog)
        prog_scopes = [s for s in scopes if s["program"] == prog]
        v = rep_mod.evaluate(f, prog_scopes, pol, reports, findings=findings, today=NOW.isoformat())
        store.upsert_reportability(v["finding_id"], verdict=v["verdict"], reason=v["reason"],
                                   priority=v["priority"], policy_quote=v["policy_quote"],
                                   next_agent=v["next_agent"])
        verdicts.append(v)
    (sim_dir / "reportability_report.md").write_text(
        rep_mod.render_report_md(verdicts, simulation=True, generated_at=NOW.isoformat()),
        encoding="utf-8")
    outputs["verdicts"] = verdicts
    log.info("reportability done", verdicts=len(verdicts))
    return outputs


def _print_summary(sim_dir: Path, outputs: Dict[str, Any]) -> None:
    print("\n" + "═" * 70)
    print(" SIMULACIÓN END-TO-END — pipeline de analista (sin red)")
    print("═" * 70)

    print("\n[-1] program_selector — ranking:")
    for r in outputs["ranking"]:
        note = f"  ({r['note']})" if r["note"] else ""
        print(f"     #{r['rank']} {r['handle']:<14} score={r['score']:<5}{note}")

    print("\n[0]  policy_parser — políticas parseadas:")
    for handle, p in outputs["policies"].items():
        floor = (p.get("severity_floor") or {}).get("value", "") or "n/d"
        print(f"     {handle:<14} secciones={len(p['sections_found'])} "
              f"excluidas={len(p['excluded_vuln_classes'])} floor={floor} "
              f"manual_review={p['needs_manual_review']}")

    print("\n[2]  attack_planner — planes generados:")
    for plan in outputs["plans"]:
        print(f"     {plan['asset']:<22} tipo={plan['asset_type']:<8} "
              f"checks={plan['checks_count']:<2} prio={plan['priority']:<6} "
              f"(excluidos: {len(plan['filtered_excluded'])})")

    print("\n[6]  reportability — veredictos:")
    for v in outputs["verdicts"]:
        print(f"     finding#{v['finding_id']} {v['verdict']:<26} "
              f"prio={v['priority'] or '-':<7} next={v['next_agent'] or '-'}")

    print(f"\n Artefactos en: {sim_dir}")
    for f in sorted(sim_dir.glob("*.md")) + sorted(sim_dir.glob("*.json")):
        print(f"   - {f.relative_to(cfg_mod.PROJECT_ROOT)}")
    print("═" * 70)


def main() -> int:
    sim_dir = cfg_mod.PROJECT_ROOT / "workspace" / "plans" / "_simulation"
    sim_dir.mkdir(parents=True, exist_ok=True)
    # Logger writes its JSONL trace to the REAL workspace/logs (audit trail) but
    # its events.csv to the ISOLATED store, so real data/*.csv stays clean.
    log = Logger(
        logs_dir=cfg_mod.PROJECT_ROOT / "workspace" / "logs",
        store=CSVStore(data_dir=sim_dir / "csv"),
        agent="simulate_session",
    )
    try:
        outputs = run(sim_dir, log)
        _print_summary(sim_dir, outputs)
        log.info("simulation completed OK")
        return 0
    except Exception as exc:  # noqa: BLE001 - report + trace, never crash silently
        tb = traceback.format_exc()
        log.error("simulation FAILED", error=str(exc), traceback=tb)
        print(f"\nSIMULATION FAILED: {exc}\n{tb}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
