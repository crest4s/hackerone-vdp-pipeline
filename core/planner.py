"""
core.planner
============

Decision engine behind ``attack_planner_agent``: given an in-scope asset, its
type and the parsed policy, produce a **prioritised, actionable** attack plan —
what a human sketches before opening Burp.

Method
------
1. Classify the asset (web_app / api / mobile / cloud / ip_red).
2. Load the matching checklist from ``config/checklists/<type>.md``.
3. Drop every item that falls under the policy's ``excluded_vuln_classes`` or a
   ``prohibited_actions`` category. If the policy is "only manual", drop
   automated-scanner items too and say so.
4. Order the survivors by ROI = ``priority_base`` modulated by bounty
   eligibility and the severity floor.
5. Tag each item quick-win (≤10 min) / deep-dive (≥60 min), with its tool and
   success criterion (what would constitute a finding).

Every checklist item is ``{id, nombre, categoria, tiempo_estimado, herramienta,
criterio_exito, prioridad_base}``; the files are plain Markdown tables so a human
can read/edit them and this module can parse them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .csvstore import utc_now
from .policy import values as policy_values

_CHECKLIST_COLUMNS = [
    "id", "nombre", "categoria", "tiempo_estimado", "herramienta",
    "criterio_exito", "prioridad_base",
]

# Words too generic to drive an exclusion match (avoid over-filtering). These
# collide across unrelated checks (e.g. "security" appears in half the items),
# so they must never be the token that triggers a policy exclusion.
_STOP = {
    "missing", "without", "documented", "impact", "enabled", "issues", "reverse",
    "login", "logout", "email", "based", "check", "test", "testing", "audit",
    "the", "and", "for", "with", "your", "into", "over", "from",
    "security", "service", "server", "access", "config", "review", "other",
    "open", "port", "page", "data", "using", "related", "weak",
}

_AUTOMATED_TOOLS = ("nuclei", "scanner", "zap", "acunetix", "burp scanner",
                    "automated", "nikto", "wpscan", "sqlmap")


# ──────────────────────────────────────────────────────────────────────────
#  Asset classification → checklist name
# ──────────────────────────────────────────────────────────────────────────
def classify_asset(asset: str, asset_type: str = "") -> str:
    at = (asset_type or "").upper()
    low = (asset or "").lower()
    if at in ("CIDR", "IP_ADDRESS") or _looks_like_ip(low):
        return "ip_red"
    if at in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA"):
        return "mobile"
    if "api" in low or "graphql" in low or at == "API":
        return "api"
    if any(k in low for k in ("aws", "amazonaws", "s3.", "s3-", "gcp",
                              "googleapis", "azure", "cloudfront", "blob.core")):
        return "cloud"
    return "web_app"


def _looks_like_ip(text: str) -> bool:
    host = text.split("/")[0].split(":")[0]
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


# ──────────────────────────────────────────────────────────────────────────
#  Checklist loading (Markdown table parser)
# ──────────────────────────────────────────────────────────────────────────
def load_checklist(path: Path) -> List[Dict[str, Any]]:
    """Parse a checklist Markdown table into a list of item dicts."""
    text = Path(path).read_text(encoding="utf-8")
    rows: List[Dict[str, Any]] = []
    header: Optional[List[str]] = None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if all(set(c) <= {"-", ":", " "} for c in cells):  # separator row
            continue
        if len(cells) < len(header):
            cells += [""] * (len(header) - len(cells))
        item = dict(zip(header, cells))
        norm = {col: item.get(col, "") for col in _CHECKLIST_COLUMNS}
        try:
            norm["tiempo_estimado"] = int(re.sub(r"[^0-9]", "", norm["tiempo_estimado"]) or 0)
        except ValueError:
            norm["tiempo_estimado"] = 0
        try:
            norm["prioridad_base"] = int(re.sub(r"[^0-9]", "", norm["prioridad_base"]) or 0)
        except ValueError:
            norm["prioridad_base"] = 0
        if norm["id"]:
            rows.append(norm)
    return rows


# ──────────────────────────────────────────────────────────────────────────
#  Filtering helpers
# ──────────────────────────────────────────────────────────────────────────
def _keywords(label: str) -> List[str]:
    label = re.sub(r"\(.*?\)", " ", label.lower())
    toks = re.split(r"[^a-z0-9]+", label)
    return [t for t in toks if len(t) >= 5 and t not in _STOP]


def _item_text(item: Dict[str, Any]) -> str:
    return f"{item.get('id','')} {item.get('nombre','')} {item.get('categoria','')}".lower()


def _matches_any(item: Dict[str, Any], labels: List[str]) -> Optional[str]:
    """Return the offending label if the item matches one of *labels*."""
    text = _item_text(item)
    for label in labels:
        kws = _keywords(label)
        if kws and any(kw in text for kw in kws):
            return label
    return None


def _is_automated(item: Dict[str, Any]) -> bool:
    tool = (item.get("herramienta", "") or "").lower()
    return any(a in tool for a in _AUTOMATED_TOOLS)


# ──────────────────────────────────────────────────────────────────────────
#  Plan construction
# ──────────────────────────────────────────────────────────────────────────
def build_plan(
    program: str,
    asset: str,
    asset_type: str,
    parsed_policy: Optional[Dict[str, Any]],
    checklist_items: List[Dict[str, Any]],
    *,
    session_id: str = "",
    bounty_eligible: bool = True,
    today: str = "",
) -> Dict[str, Any]:
    parsed_policy = parsed_policy or {}
    checklist = classify_asset(asset, asset_type)

    excluded_labels = policy_values(parsed_policy.get("excluded_vuln_classes", []))
    prohibited_labels = policy_values(parsed_policy.get("prohibited_actions", []))
    red_flags = policy_values(parsed_policy.get("red_flags", []))
    manual_only = any("manual" in rf.lower() for rf in red_flags)
    severity_floor = (parsed_policy.get("severity_floor") or {}).get("value", "") \
        if isinstance(parsed_policy.get("severity_floor"), dict) else ""

    checks: List[Dict[str, Any]] = []
    filtered_excluded: List[Dict[str, str]] = []
    filtered_prohibited: List[Dict[str, str]] = []
    filtered_manual: List[Dict[str, str]] = []

    for item in checklist_items:
        hit = _matches_any(item, excluded_labels)
        if hit:
            filtered_excluded.append({"id": item["id"], "nombre": item["nombre"], "reason": hit})
            continue
        hit = _matches_any(item, prohibited_labels)
        if hit:
            filtered_prohibited.append({"id": item["id"], "nombre": item["nombre"], "reason": hit})
            continue
        if manual_only and _is_automated(item):
            filtered_manual.append({"id": item["id"], "nombre": item["nombre"],
                                    "reason": "automated tool disallowed (política 'solo manual')"})
            continue

        adjusted = float(item.get("prioridad_base", 0))
        if not bounty_eligible:
            adjusted *= 0.85
        # Demote low-ROI items when the program only accepts high/critical.
        if severity_floor in ("high", "critical") and item.get("prioridad_base", 0) <= 2:
            adjusted *= 0.5

        t = int(item.get("tiempo_estimado", 0) or 0)
        bucket = "quick_win" if t and t <= 10 else ("deep_dive" if t >= 60 else "medium")

        checks.append({
            **item,
            "adjusted_priority": round(adjusted, 2),
            "bucket": bucket,
        })

    checks.sort(key=lambda c: (-c["adjusted_priority"], c.get("tiempo_estimado", 0)))

    top = checks[0]["adjusted_priority"] if checks else 0
    if top >= 4 and bounty_eligible:
        overall = "high"
    elif top >= 3:
        overall = "medium"
    else:
        overall = "low"

    return {
        "program": program,
        "asset": asset,
        "asset_type": checklist,
        "raw_asset_type": asset_type,
        "session_id": session_id,
        "created_at": today or utc_now(),
        "manual_only": manual_only,
        "bounty_eligible": bounty_eligible,
        "severity_floor": severity_floor,
        "priority": overall,
        "checks": checks,
        "checks_count": len(checks),
        "filtered_excluded": filtered_excluded,
        "filtered_prohibited": filtered_prohibited,
        "filtered_manual": filtered_manual,
    }


def render_plan_md(plan: Dict[str, Any], *, simulation: bool = False) -> str:
    tag = "  ·  **SIMULACIÓN**" if simulation else ""
    lines = [
        f"# Plan de ataque — `{plan['asset']}` ({plan['asset_type']}){tag}",
        "",
        f"- **Programa:** `{plan['program']}`  ·  **Sesión:** {plan['session_id'] or '—'}",
        f"- **Prioridad del plan:** `{plan['priority']}`  ·  **Checks:** {plan['checks_count']}",
        f"- **Bounty elegible:** {'sí' if plan['bounty_eligible'] else 'no'}"
        f"  ·  **Severity floor:** `{plan['severity_floor'] or 'n/d'}`",
    ]
    if plan["manual_only"]:
        lines.append("- ⚠️ **Política 'solo manual':** se han excluido herramientas automatizadas.")
    lines += ["", "## Checks priorizados (ROI: prob × severidad × elegibilidad)", ""]
    lines += ["| # | prio | check | categoría | tiempo | herramienta | tipo | criterio de éxito |",
              "|---|-----:|-------|-----------|-------:|-------------|------|-------------------|"]
    bucket_es = {"quick_win": "quick win", "deep_dive": "deep dive", "medium": "medio"}
    for i, c in enumerate(plan["checks"], 1):
        lines.append(
            f"| {i} | {c['adjusted_priority']} | {c['nombre']} | {c['categoria']} | "
            f"{c['tiempo_estimado']}m | {c['herramienta']} | {bucket_es.get(c['bucket'], c['bucket'])} | "
            f"{c['criterio_exito']} |"
        )
    lines.append("")

    def _filtered(title: str, items: List[Dict[str, str]]) -> None:
        if not items:
            return
        lines.append(f"## {title}")
        for it in items:
            lines.append(f"- `{it['id']}` {it['nombre']} — _{it['reason']}_")
        lines.append("")

    _filtered("Excluidos por política (excluded_vuln_classes)", plan["filtered_excluded"])
    _filtered("Excluidos por prohibición (prohibited_actions)", plan["filtered_prohibited"])
    _filtered("Excluidos por 'solo manual'", plan["filtered_manual"])
    return "\n".join(lines) + "\n"
