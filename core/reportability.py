"""
core.reportability
==================

Decision engine behind ``reportability_agent``: the *final filter* that decides
whether a finding is worth writing up **before** any time goes into a report.

The decision follows a fixed, ordered ladder (first rule that applies wins) so
every verdict is deterministic and auditable:

  1. asset not in scope                       → ``not_reportable_scope``
  2. asset eligible_for_submission = false    → ``not_reportable_submission``
  3. vuln class in excluded_vuln_classes      → ``not_reportable_excluded``
  4. severity < severity_floor                → ``not_reportable_severity``
  5. asset max_severity < finding severity    → ``report_later_low_return``
  6. asset eligible_for_bounty = false        → ``reportable_no_bounty``
  7. dedup_hash already submitted             → ``already_reported``
  8. everything passes                        → ``report_now`` (+ priority)

Scope containment reuses :mod:`core.scope` (wildcards never cover their apex,
exclusions win) and severity comparison reuses :mod:`core.severity` — no logic
is duplicated here.

Hard rules: never invokes ``reporter_agent`` (only *suggests* a next agent);
missing critical info → ``needs_manual_review`` rather than a guess; ambiguity
is denied by default.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import scope as scope_mod
from .csvstore import utc_now
from .severity import meets_floor, normalize_severity, severity_rank

_STOP = {
    "missing", "without", "documented", "impact", "enabled", "issues", "reverse",
    "login", "logout", "email", "based", "the", "and", "for", "with", "your",
    "security", "service", "server", "access", "config", "review", "other",
    "open", "port", "page", "data", "using", "related", "weak", "test", "testing",
}

_REPORTER = "reporter_agent"


def _keywords(label: str) -> List[str]:
    label = re.sub(r"\(.*?\)", " ", (label or "").lower())
    toks = re.split(r"[^a-z0-9]+", label)
    return [t for t in toks if len(t) >= 4 and t not in _STOP]


def _match_excluded(vuln_text: str, excluded_items: List[Any]) -> Optional[Dict[str, str]]:
    """Return the excluded-class item whose keywords appear in *vuln_text*."""
    text = (vuln_text or "").lower()
    for it in excluded_items:
        label = it.get("value", "") if isinstance(it, dict) else str(it)
        kws = _keywords(label)
        if kws and any(kw in text for kw in kws):
            return it if isinstance(it, dict) else {"value": label, "source_quote": ""}
    return None


def _priority(severity: str, bounty_eligible: bool, is_core: bool) -> str:
    """Priority table from the spec (with sensible gap-fills)."""
    r = severity_rank(severity)  # none0 low1 medium2 high3 critical4
    if bounty_eligible:
        if r >= 3 and is_core:
            return "high"
        if r >= 3:
            return "medium"   # high/critical but not a core asset
        if r == 2:
            return "medium"   # medium + bounty
        return "low"          # low (or none) + bounty
    # no bounty
    if r >= 3:
        return "medium"       # high/critical + no bounty
    return "low"              # medium/low + no bounty


def _find_scope_row(scopes: List[Dict[str, Any]], program: str, matched_asset: str) -> Optional[Dict[str, Any]]:
    for s in scopes:
        if s.get("program", program) == program and s.get("asset") == matched_asset:
            return s
    return None


def evaluate(
    finding: Dict[str, Any],
    scopes: List[Dict[str, Any]],
    parsed_policy: Optional[Dict[str, Any]],
    reports: List[Dict[str, Any]],
    *,
    findings: Optional[List[Dict[str, Any]]] = None,
    today: str = "",
) -> Dict[str, Any]:
    """Evaluate one *finding*'s reportability. Returns a verdict dict."""
    program = finding.get("program", "")
    asset = finding.get("asset", "")
    severity = normalize_severity(finding.get("severity", ""))
    vuln_text = f"{finding.get('vuln_class','')} {finding.get('title','')} {finding.get('cwe','')}"

    def verdict(v: str, reason: str, *, priority: str = "", quote: str = "", nxt: str = "") -> Dict[str, Any]:
        return {
            "finding_id": finding.get("id", ""),
            "program": program,
            "asset": asset,
            "severity": severity,
            "vuln_class": finding.get("vuln_class", "") or finding.get("title", ""),
            "verdict": v,
            "reason": reason,
            "priority": priority,
            "policy_quote": quote,
            "next_agent": nxt,
            "evaluated_at": today or utc_now(),
        }

    # Deny-by-default: no parsed policy → cannot decide safely.
    if not parsed_policy:
        return verdict("needs_manual_review",
                       "sin política parseada para el programa (deny-by-default)")

    prog_scopes = [s for s in scopes if s.get("program", program) == program]

    # Rule 1 — scope containment (reuses core.scope: exclusions win, apex safe).
    decision = scope_mod.validate(asset, prog_scopes, program=program)
    if not decision.allowed:
        return verdict("not_reportable_scope", decision.reason)

    srow = _find_scope_row(prog_scopes, program, decision.matched_asset) or {}

    def _is_true(x: Any, default: bool = True) -> bool:
        s = str(x).strip().lower()
        if s == "":
            return default
        return s in ("1", "true", "yes", "y")

    # Rule 2 — submission eligibility.
    if not _is_true(srow.get("eligible_for_submission", "true")):
        return verdict("not_reportable_submission",
                       f"asset '{decision.matched_asset}' no acepta submissions (eligible_for_submission=false)")

    # Rule 3 — excluded vuln class.
    excl = _match_excluded(vuln_text, parsed_policy.get("excluded_vuln_classes", []))
    if excl:
        return verdict("not_reportable_excluded",
                       f"clase de vuln excluida por política: {excl.get('value','')}",
                       quote=excl.get("source_quote", ""))

    # Rule 4 — severity floor.
    floor = (parsed_policy.get("severity_floor") or {}).get("value", "") \
        if isinstance(parsed_policy.get("severity_floor"), dict) else ""
    if floor and not meets_floor(severity, floor):
        return verdict("not_reportable_severity",
                       f"severidad {severity} < severity_floor {floor}",
                       quote=(parsed_policy.get("severity_floor") or {}).get("source_quote", ""))

    # Rule 5 — asset max severity caps the finding's return.
    sev_max = srow.get("severity_max", "")
    if sev_max and severity_rank(severity) > severity_rank(sev_max):
        return verdict("report_later_low_return",
                       f"severidad {severity} supera el max_severity del asset ({sev_max}): bajo retorno")

    bounty_eligible = _is_true(srow.get("eligible_for_bounty", "false"), default=False)
    is_core = severity_rank(sev_max) >= severity_rank("high")

    # Rule 6 — bounty ineligible (still reportable, just no money).
    if not bounty_eligible:
        pr = _priority(severity, False, is_core)
        return verdict("reportable_no_bounty",
                       f"asset sin bounty (eligible_for_bounty=false); reportable por reputación",
                       priority=pr, nxt=_REPORTER)

    # Rule 7 — already reported (a submitted report for the same dedup hash).
    dedup = finding.get("dedup_hash", "")
    if dedup:
        hash_by_fid = {f.get("id"): f.get("dedup_hash") for f in (findings or [])}
        for r in reports:
            if str(r.get("state", "")).lower() == "submitted" and \
                    hash_by_fid.get(r.get("finding_id")) == dedup:
                return verdict("already_reported",
                               f"ya existe un reporte submitted con el mismo dedup_hash (finding {r.get('finding_id')})",
                               nxt="memory_agent")

    # Rule 8 — report now.
    pr = _priority(severity, True, is_core)
    return verdict("report_now",
                   f"pasa todos los filtros; severidad {severity}, bounty elegible, "
                   f"asset {'core' if is_core else 'no-core'}",
                   priority=pr, nxt=_REPORTER)


def render_report_md(
    verdicts: List[Dict[str, Any]],
    *,
    simulation: bool = False,
    generated_at: str = "",
) -> str:
    tag = "  ·  **SIMULACIÓN**" if simulation else ""
    lines = [
        f"# Reportability — reportability_agent{tag}",
        "",
        f"_Generado: {generated_at}_" if generated_at else "",
        "",
        "| finding | asset | sev | veredicto | prioridad | siguiente | motivo |",
        "|---------|-------|-----|-----------|-----------|-----------|--------|",
    ]
    for v in verdicts:
        lines.append(
            f"| {v['finding_id']} | `{v['asset']}` | {v['severity']} | "
            f"**{v['verdict']}** | {v['priority'] or '—'} | {v['next_agent'] or '—'} | {v['reason']} |"
        )
    lines.append("")
    quoted = [v for v in verdicts if v.get("policy_quote")]
    if quoted:
        lines += ["## Citas de política (auditoría)", ""]
        for v in quoted:
            lines.append(f"- finding {v['finding_id']} → _{v['policy_quote']}_")
        lines.append("")
    return "\n".join(x for x in lines if x is not None) + "\n"
