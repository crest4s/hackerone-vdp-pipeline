"""
core.scoring
============

Decision engine behind ``program_selector_agent``: rank HackerOne programs by
how attractive they are to work **today**, the way an analyst eyeballs their
portfolio when they open the laptop.

Design
------
* Pure Python, no LLM, no network. Every input is a plain list of dict rows
  (as returned by :class:`core.store.Store`), so the same function powers both
  ``scripts/rank_programs.py`` (real ``data/*.csv``) and
  ``scripts/simulate_session.py`` (isolated demo rows).
* Seven documented, individually-weighted criteria (weights live in
  ``config/scoring.yaml``). Every criterion is reduced to a ``0..1`` score; the
  final score is the weighted mean, scaled to ``0..100``.
* Hard rules:
    - ``enabled: false`` programs are **never** ranked/recommended.
    - Programs with no history are flagged ``sin histórico, decisión por
      política`` and nudged by how permissive their parsed policy is.
    - Ties break in favour of **fewer days since the last session** (continuity
      / momentum).

The seven criteria (all "higher score = more attractive"):
  1. bounty       — active bounty + median historical ``bounty_amount``.
  2. triage_speed — median days submitted→triaged (faster is better).
  3. scope        — number of in-scope assets + variety of asset types.
  4. competition  — subjective saturation 0..1 from config (inverted).
  5. skill_fit    — overlap of the program's asset skills with ``skill_set``.
  6. freshness    — days since last session (un-worked surface = opportunity).
  7. saturation   — days since last OPEN finding vs ``saturacion_umbral_dias``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .csvstore import days_since
from .severity import severity_rank

CRITERIA = [
    "bounty",
    "triage_speed",
    "scope",
    "competition",
    "skill_fit",
    "freshness",
    "saturation",
]

# Sensible defaults if config/scoring.yaml omits a weight.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "bounty": 0.25,
    "triage_speed": 0.15,
    "scope": 0.15,
    "competition": 0.10,
    "skill_fit": 0.15,
    "freshness": 0.10,
    "saturation": 0.10,
}

OPEN_STATUSES = {"new", "triaged", "needs-info", "reported"}

# Map HackerOne asset_type values → the skill tags used in scoring.yaml.
_ASSET_TYPE_SKILLS = {
    "URL": ["web"],
    "WILDCARD": ["web"],
    "CIDR": ["network"],
    "IP_ADDRESS": ["network"],
    "GOOGLE_PLAY_APP_ID": ["mobile"],
    "APPLE_STORE_APP_ID": ["mobile"],
    "OTHER_APK": ["mobile"],
    "OTHER_IPA": ["mobile"],
    "SOURCE_CODE": ["code"],
    "SMART_CONTRACT": ["blockchain"],
    "OTHER": [],
}


# ──────────────────────────────────────────────────────────────────────────
#  Small numeric helpers
# ──────────────────────────────────────────────────────────────────────────
def _median(values: List[float]) -> Optional[float]:
    nums = sorted(v for v in values if v is not None)
    if not nums:
        return None
    mid = len(nums) // 2
    if len(nums) % 2:
        return nums[mid]
    return (nums[mid - 1] + nums[mid]) / 2.0


def _to_float(value: Any) -> Optional[float]:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "y")


def _minmax(
    raw: Dict[str, Optional[float]],
    *,
    higher_is_better: bool = True,
    none_fill: float = 0.5,
) -> Dict[str, float]:
    """Min-max normalise a {handle: value} map to 0..1 across the candidate set."""
    nums = [v for v in raw.values() if v is not None]
    if not nums:
        return {k: none_fill for k in raw}
    lo, hi = min(nums), max(nums)
    out: Dict[str, float] = {}
    for handle, value in raw.items():
        if value is None:
            out[handle] = none_fill
        elif hi == lo:
            out[handle] = 0.5
        else:
            norm = (value - lo) / (hi - lo)
            out[handle] = norm if higher_is_better else (1.0 - norm)
    return out


# ──────────────────────────────────────────────────────────────────────────
#  Skill-fit + policy permissiveness
# ──────────────────────────────────────────────────────────────────────────
def _asset_skill_tags(asset: str, asset_type: str) -> List[str]:
    tags = list(_ASSET_TYPE_SKILLS.get((asset_type or "").upper(), []))
    low = (asset or "").lower()
    if "api" in low or "graphql" in low:
        tags.append("api")
    if any(k in low for k in ("aws", "amazonaws", "s3.", "gcp", "azure", "cloudfront")):
        tags.append("cloud")
    return tags or ["web"]  # default unknown web-ish surface to web


def _skill_fit(scopes: List[Dict[str, str]], skill_set: List[str]) -> Optional[float]:
    """Fraction of a program's in-scope-asset skill tags covered by skill_set."""
    if not scopes:
        return None
    wanted = {s.strip().lower() for s in skill_set if s.strip()}
    if not wanted:
        return 0.5
    present: set = set()
    for row in scopes:
        if not _is_true(row.get("in_scope", "true")):
            continue
        present.update(_asset_skill_tags(row.get("asset", ""), row.get("asset_type", "")))
    if not present:
        return None
    covered = present & wanted
    return len(covered) / len(present)


def policy_permissiveness(policy: Optional[Dict[str, Any]]) -> float:
    """
    Rough 0..1 permissiveness score for a parsed policy (1 = very permissive).

    Used only for programs with no history, to decide by policy. Deny-by-default:
    a missing or manual-review policy is treated as restrictive (0.3).
    """
    if not policy:
        return 0.3  # deny-by-default: no policy → treat as restrictive
    score = 0.6  # neutral-ish baseline for a clean, parsed policy
    red_flags = policy.get("red_flags") or []
    prohibited = policy.get("prohibited_actions") or []
    allowed = policy.get("allowed_testing") or []

    def _n(x):
        return len(x) if isinstance(x, (list, tuple)) else 0

    if any("manual" in str(r).lower() for r in red_flags):
        score -= 0.3
    if any("automat" in str(a).lower() for a in allowed):
        score += 0.2
    score -= 0.05 * _n(prohibited)
    floor = policy.get("severity_floor")
    floor_val = str(floor.get("value", "") if isinstance(floor, dict) else floor or "").lower()
    if floor_val in ("high", "critical"):
        score -= 0.2
    # A manual-review flag is a mild caution, not a verdict of "restrictive"
    # (it fires for benign gaps like an unstated severity floor).
    if _is_true(policy.get("needs_manual_review", "false")):
        score -= 0.1
    return max(0.0, min(1.0, score))


# ──────────────────────────────────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────────────────────────────────
def score_programs(
    programs: List[Dict[str, Any]],
    reports: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    scopes: List[Dict[str, Any]],
    scoring_cfg: Dict[str, Any],
    *,
    policies: Optional[List[Dict[str, Any]]] = None,
    today: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Rank *programs* (only ``enabled`` ones) best-first.

    Returns a list of result dicts, each with per-criterion breakdown, the
    weighted total (0..100), a human note, and ``days_since_last_session``.
    """
    now = today or datetime.now(timezone.utc)
    weights = {**DEFAULT_WEIGHTS, **{k: float(v) for k, v in (scoring_cfg.get("weights") or {}).items()}}
    skill_set = list(scoring_cfg.get("skill_set") or [])
    sat_threshold = float(scoring_cfg.get("saturacion_umbral_dias", 14) or 14)
    competencia = scoring_cfg.get("competencia_programas") or {}
    policy_by_prog = {p.get("program"): p for p in (policies or [])}

    # finding_id → program, for attributing report bounties/triage to a program.
    finding_program = {f.get("id"): f.get("program") for f in findings}

    # Only rank enabled programs (hard rule). Disabled ones are reported apart.
    enabled_programs = [p for p in programs if _is_true(p.get("enabled", "false"))]

    # ── gather raw per-program metrics ────────────────────────────────────
    raw_bounty: Dict[str, Optional[float]] = {}
    raw_triage: Dict[str, Optional[float]] = {}
    raw_scope: Dict[str, Optional[float]] = {}
    raw_freshness: Dict[str, Optional[float]] = {}
    abs_competition: Dict[str, float] = {}
    abs_skill: Dict[str, Optional[float]] = {}
    abs_saturation: Dict[str, float] = {}
    meta: Dict[str, Dict[str, Any]] = {}

    for prog in enabled_programs:
        handle = prog.get("handle", "")
        prog_scopes = [s for s in scopes if s.get("program") == handle]
        prog_reports = [
            r for r in reports if finding_program.get(r.get("finding_id")) == handle
        ]
        prog_findings = [f for f in findings if f.get("program") == handle]
        prog_sessions = [s for s in sessions if s.get("program") == handle]

        # 1) bounty: median historical bounty, discounted if bounty is inactive.
        bounties = [
            b for b in (_to_float(r.get("bounty_amount")) for r in prog_reports)
            if b and b > 0
        ]
        median_b = _median(bounties) or 0.0
        offers = _is_true(prog.get("bounty", "false"))
        raw_bounty[handle] = median_b if offers else median_b * 0.25

        # 2) triage speed: median days submitted→triaged (lower is better).
        triage_days = []
        for r in prog_reports:
            sub, tri = r.get("submitted_at"), r.get("triaged_at")
            d_sub, d_tri = days_since(sub, now), days_since(tri, now)
            if d_sub is not None and d_tri is not None:
                delta = d_sub - d_tri  # (now-sub) - (now-tri) = tri - sub, in days
                if delta >= 0:
                    triage_days.append(delta)
        raw_triage[handle] = _median(triage_days)

        # 3) scope size + variety.
        in_scope = [s for s in prog_scopes if _is_true(s.get("in_scope", "true"))]
        variety = len({(s.get("asset_type") or "").upper() for s in in_scope if s.get("asset_type")})
        raw_scope[handle] = float(len(in_scope)) + 2.0 * float(variety)

        # 4) competition (subjective 0..1 from config; invert → attractiveness).
        comp = _to_float(competencia.get(handle))
        abs_competition[handle] = 1.0 - (comp if comp is not None else 0.5)

        # 5) skill fit.
        abs_skill[handle] = _skill_fit(prog_scopes, skill_set)

        # 6) freshness: days since last session (never → maximally fresh).
        sess_days = [d for d in (days_since(s.get("started_at"), now) for s in prog_sessions) if d is not None]
        last_session_days = min(sess_days) if sess_days else None
        raw_freshness[handle] = last_session_days  # None handled as fresh below

        # 7) saturation: days since last OPEN finding vs threshold.
        open_finding_days = [
            d for d in (
                days_since(f.get("created_at"), now)
                for f in prog_findings if (f.get("status") or "") in OPEN_STATUSES
            ) if d is not None
        ]
        if not open_finding_days:
            abs_saturation[handle] = 1.0  # nothing open → not saturated
        else:
            recent = min(open_finding_days)
            abs_saturation[handle] = min(1.0, recent / sat_threshold) if sat_threshold > 0 else 1.0

        meta[handle] = {
            "program": prog,
            "has_history": bool(prog_reports or prog_findings or prog_sessions),
            "days_since_last_session": last_session_days,
            "in_scope_assets": len(in_scope),
            "asset_variety": variety,
            "median_bounty": median_b,
            "offers_bounty": offers,
            "median_triage_days": _median(triage_days),
        }

    # ── normalise cross-program criteria ──────────────────────────────────
    norm_bounty = _minmax(raw_bounty, higher_is_better=True, none_fill=0.0)
    norm_triage = _minmax(raw_triage, higher_is_better=False, none_fill=0.5)
    norm_scope = _minmax(raw_scope, higher_is_better=True, none_fill=0.0)
    # freshness: more days = fresher; never worked (None) fills to the top.
    norm_fresh = _minmax(raw_freshness, higher_is_better=True, none_fill=1.0)
    # skill_fit is ALREADY an absolute 0..1 fraction — do NOT min-max it (that
    # would flatten a perfectly good 0.75 to 0 just because it is the local min).
    norm_skill = {h: (v if v is not None else 0.4) for h, v in abs_skill.items()}

    # ── assemble, weight, and note ────────────────────────────────────────
    results: List[Dict[str, Any]] = []
    weight_sum = sum(weights.get(c, 0.0) for c in CRITERIA) or 1.0

    for handle in meta:
        scores = {
            "bounty": norm_bounty[handle],
            "triage_speed": norm_triage[handle],
            "scope": norm_scope[handle],
            "competition": abs_competition[handle],
            "skill_fit": norm_skill[handle],
            "freshness": norm_fresh[handle],
            "saturation": abs_saturation[handle],
        }
        weighted = sum(weights.get(c, 0.0) * scores[c] for c in CRITERIA) / weight_sum
        total = round(100.0 * weighted, 1)

        note = ""
        m = meta[handle]
        if not m["has_history"]:
            # Decide by policy: permissive → nudge up, restrictive → down.
            perm = policy_permissiveness(policy_by_prog.get(handle))
            total = round(0.6 * total + 0.4 * (perm * 100.0), 1)
            note = "sin histórico, decisión por política"

        results.append(
            {
                "handle": handle,
                "name": m["program"].get("name", handle),
                "score": total,
                "criteria": {c: round(scores[c], 3) for c in CRITERIA},
                "weights": {c: round(weights.get(c, 0.0), 3) for c in CRITERIA},
                "note": note,
                "has_history": m["has_history"],
                "days_since_last_session": (
                    round(m["days_since_last_session"], 1)
                    if m["days_since_last_session"] is not None else None
                ),
                "in_scope_assets": m["in_scope_assets"],
                "asset_variety": m["asset_variety"],
                "median_bounty": round(m["median_bounty"], 2),
                "offers_bounty": m["offers_bounty"],
                "median_triage_days": (
                    round(m["median_triage_days"], 1)
                    if m["median_triage_days"] is not None else None
                ),
            }
        )

    # Sort: score desc, then FEWER days since last session wins the tie
    # (never worked → +inf → loses the tie-break, i.e. continuity is preferred).
    def _sort_key(r: Dict[str, Any]):
        d = r["days_since_last_session"]
        return (-r["score"], d if d is not None else float("inf"))

    results.sort(key=_sort_key)
    for i, r in enumerate(results, 1):
        r["rank"] = i
    return results


# ──────────────────────────────────────────────────────────────────────────
#  Markdown rendering
# ──────────────────────────────────────────────────────────────────────────
def render_ranking_md(
    ranked: List[Dict[str, Any]],
    *,
    top_n: int = 3,
    generated_at: str = "",
    disabled: Optional[List[Dict[str, Any]]] = None,
    simulation: bool = False,
    recommendation: str = "",
) -> str:
    tag = "  ·  **SIMULACIÓN**" if simulation else ""
    lines = [
        f"# Ranking de programas — program_selector_agent{tag}",
        "",
        f"_Generado: {generated_at}_" if generated_at else "",
        "",
        "Score 0–100 = media ponderada de 7 criterios "
        "(bounty · triage · scope · competencia · skill · freshness · saturación).",
        "",
        "| # | programa | score | bounty | triage | scope | comp | skill | fresh | sat | nota |",
        "|---|----------|------:|-------:|-------:|------:|-----:|------:|------:|----:|------|",
    ]
    for r in ranked:
        c = r["criteria"]
        lines.append(
            f"| {r['rank']} | `{r['handle']}` | **{r['score']}** | "
            f"{c['bounty']:.2f} | {c['triage_speed']:.2f} | {c['scope']:.2f} | "
            f"{c['competition']:.2f} | {c['skill_fit']:.2f} | {c['freshness']:.2f} | "
            f"{c['saturation']:.2f} | {r['note'] or '—'} |"
        )
    lines += ["", f"## TOP {min(top_n, len(ranked))} — por qué", ""]
    for r in ranked[:top_n]:
        why = _explain(r)
        lines.append(f"### {r['rank']}. `{r['handle']}` — score {r['score']}")
        for w in why:
            lines.append(f"- {w}")
        lines.append("")

    if not recommendation and ranked:
        top = ranked[0]
        recommendation = (
            f"**Empieza hoy por `{top['handle']}`** (score {top['score']}): "
            + "; ".join(_explain(top)[:2]) + "."
        )
    lines += ["## Recomendación", "", recommendation or "_Sin programas habilitados que rankear._", ""]

    if disabled:
        lines += [
            "## Excluidos (enabled: false — nunca recomendados)",
            "",
            ", ".join(f"`{d.get('handle')}`" for d in disabled),
            "",
        ]
    return "\n".join(x for x in lines if x is not None) + "\n"


def _explain(r: Dict[str, Any]) -> List[str]:
    """3–5 human reasons a program ranks where it does."""
    c = r["criteria"]
    out: List[str] = []
    if r["note"]:
        out.append(f"{r['note']} — se prioriza según lo permisiva que es la política.")
    if r["offers_bounty"] and r["median_bounty"] > 0:
        out.append(f"paga bounty; mediana histórica ≈ {r['median_bounty']:.0f}.")
    elif not r["offers_bounty"]:
        out.append("no paga bounty (o inactivo): atractivo reducido.")
    if r["median_triage_days"] is not None:
        out.append(f"triage rápido: mediana {r['median_triage_days']:.0f} días submitted→triaged.")
    out.append(
        f"scope: {r['in_scope_assets']} activos in-scope, {r['asset_variety']} tipos distintos "
        f"(score scope {c['scope']:.2f})."
    )
    if c["skill_fit"] >= 0.6:
        out.append(f"buen encaje con tu skill set (skill_fit {c['skill_fit']:.2f}).")
    if r["days_since_last_session"] is None:
        out.append("nunca trabajado: superficie fresca sin explorar.")
    elif c["freshness"] >= 0.6:
        out.append(f"llevas {r['days_since_last_session']:.0f} días sin tocarlo: superficie fresca.")
    if c["saturation"] < 0.5:
        out.append("saturación personal alta: tienes findings abiertos recientes ahí.")
    return out[:5]
