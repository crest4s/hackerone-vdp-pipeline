"""
core.policy
===========

Decision engine behind ``policy_parser_agent``: turn a program's free-text
policy (the ``policy_md`` column of ``data/programs.csv`` plus the textual
"Out of Scope" of the structured-scope JSON) into an **actionable** structure.

Method (documented, NOT naïve whole-document regex)
---------------------------------------------------
1. **Segment** the Markdown into sections by detecting heading-like lines
   (ATX ``#``, fully-bold lines, ``Trailing colon:`` labels, ALL-CAPS labels)
   and classifying each to a canonical section (In Scope / Out of Scope /
   Excluded / Prohibited / Rules of Engagement / Reporting Requirements /
   Rewards / Response Targets).
2. For each field, run its heuristic **only over the sections that govern it**
   (e.g. ``allowed_testing`` is read from Rules-of-Engagement / In-Scope, never
   from Out-of-Scope), matching against small, documented vocabularies.
3. Every extracted item carries a ``source_quote`` — the literal fragment it was
   derived from — so every downstream decision is auditable.

Hard rules
----------
* Never invent a rule that is not in the text.
* If a governing section is missing / unclear → ``needs_manual_review = True``
  and the gap is listed in ``manual_review_reasons``.
* **Deny-by-default:** we are liberal detecting *prohibitions* and *exclusions*
  (the safe direction) and strict detecting *allowed_testing* (an explicit
  statement is required, otherwise it stays empty and is flagged).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .csvstore import utc_now
from .severity import SEVERITY_ORDER

# ──────────────────────────────────────────────────────────────────────────
#  Section classification
# ──────────────────────────────────────────────────────────────────────────
# Ordered most-specific-first: the first canonical whose any keyword is a
# substring of the (lower-cased) heading wins.
_SECTION_KEYWORDS: List[Tuple[str, List[str]]] = [
    ("out_of_scope", ["out of scope", "out-of-scope", "not in scope", "outside scope"]),
    ("excluded", [
        "excluded", "exclusion", "not eligible", "ineligible", "non-qualifying",
        "non qualifying", "do not qualify", "does not qualify", "known issues",
        "false positive", "not accepted", "not rewarded", "will not be accepted",
        "out of bounty", "won't fix",
    ]),
    ("reporting_requirements", [
        "reporting requirement", "how to report", "report requirement",
        "submission", "submit", "disclosure", "report format", "reporting",
    ]),
    ("rewards", ["reward", "bounty", "bounties", "payout", "swag", "compensation"]),
    ("response_targets", ["response target", "response efficiency", "sla",
                          "response time", "time to bounty", "time to triage"]),
    ("prohibited", ["prohibited", "forbidden", "restriction", "restricted",
                    "do not", "don't", "never", "not allowed", "must not"]),
    ("rules_of_engagement", ["rules of engagement", "engagement", "testing rules",
                             "ground rules", "guideline", "rules", "how we work",
                             "expectations", "testing policy"]),
    ("in_scope", ["in scope", "in-scope", "scope", "targets", "assets", "domains"]),
]

_ATX = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_BOLD_ONLY = re.compile(r"^\s*(?:\*\*|__)(.+?)(?:\*\*|__)\s*:?\s*$")
_BULLET = re.compile(r"^\s*(?:[-*+•]|\d+[.)])\s+(.*)$")


def _classify_heading(text: str) -> Optional[str]:
    low = text.strip().lower()
    if not low:
        return None
    for canon, kws in _SECTION_KEYWORDS:
        if any(kw in low for kw in kws):
            return canon
    return "other"


def _is_heading(line: str) -> Optional[str]:
    """Return the heading text if *line* looks like a heading, else None."""
    m = _ATX.match(line)
    if m:
        return m.group(1)
    m = _BOLD_ONLY.match(line)
    if m:
        return m.group(1)
    stripped = line.strip()
    if not stripped or _BULLET.match(line):
        return None
    # "Trailing colon:" label — short, no mid-sentence period.
    if stripped.endswith(":") and len(stripped) <= 60 and stripped.count(".") == 0:
        return stripped[:-1]
    # ALL-CAPS short label.
    letters = [c for c in stripped if c.isalpha()]
    if letters and len(stripped) <= 60 and stripped.upper() == stripped and stripped.lower() != stripped:
        return stripped
    return None


def segment_sections(markdown: str) -> Dict[str, List[str]]:
    """
    Split policy Markdown into ``{canonical_section: [body lines]}``.

    A setext underline (``===`` / ``---``) promotes the previous line to a
    heading. Lines before any heading go under ``"preamble"``.
    """
    sections: Dict[str, List[str]] = {}
    current = "preamble"
    lines = markdown.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        # Setext heading: a text line underlined by === or ---.
        if line.strip() and re.match(r"^\s*(=|-){3,}\s*$", nxt):
            canon = _classify_heading(line.strip()) or "other"
            current = canon
            sections.setdefault(current, [])
            i += 2
            continue
        heading = _is_heading(line)
        if heading is not None:
            current = _classify_heading(heading) or "other"
            sections.setdefault(current, [])
        else:
            sections.setdefault(current, []).append(line)
        i += 1
    return sections


def _fragments(lines: List[str]) -> List[str]:
    """Yield clean candidate fragments (bullets and sentences) for matching."""
    out: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _BULLET.match(raw)
        if m:
            out.append(m.group(1).strip())
            continue
        # Sentence-split plain prose so a source_quote is a phrase, not a page.
        for sentence in re.split(r"(?<=[.;])\s+", line):
            s = sentence.strip()
            if s:
                out.append(s)
    return out


def _clip(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", text).strip().strip("*_`")
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ──────────────────────────────────────────────────────────────────────────
#  Vocabularies  (phrase → canonical label)
# ──────────────────────────────────────────────────────────────────────────
_PROHIBITED_VOCAB: List[Tuple[List[str], str]] = [
    (["denial of service", "denial-of-service", "ddos", " dos ", "dos attack"], "Denial of Service (DoS/DDoS)"),
    (["fuzz", "fuzzing"], "Aggressive fuzzing"),
    (["spam", "spamming"], "Spam"),
    (["social engineering", "phishing", "vishing", "smishing"], "Social engineering / phishing"),
    (["physical"], "Physical attacks"),
    (["brute force", "brute-force", "credential stuffing", "password spray"], "Brute force / credential stuffing"),
    (["automated scan", "automated tool", "automated testing", "scanner", "scanning tools"], "Automated scanning"),
    (["malware", "ransomware"], "Malware"),
    (["destroy data", "delete data", "modify data", "data exfiltration", "exfiltrate"], "Destructive / data-altering actions"),
    (["disrupt", "degrade", "availability"], "Actions that disrupt availability"),
]

_EXCLUDED_VOCAB: List[Tuple[List[str], str]] = [
    (["self-xss", "self xss"], "Self-XSS"),
    (["missing header", "security header", "missing security headers", "x-frame-options",
      "content-security-policy", "hsts", "x-content-type"], "Missing security headers"),
    (["clickjacking", "ui redress"], "Clickjacking (without documented impact)"),
    (["open redirect"], "Open redirect (without impact)"),
    (["rate limit", "rate-limit", "rate limiting", "lack of rate"], "Missing rate limiting"),
    (["spf", "dkim", "dmarc"], "SPF/DKIM/DMARC / email spoofing"),
    (["content spoofing", "text injection"], "Content spoofing / text injection"),
    (["banner grab", "version disclosure", "software version", "version banner"], "Version / banner disclosure"),
    (["verbose error", "stack trace", "descriptive error", "error message"], "Verbose errors / stack traces"),
    (["best practice", "informational", "informative"], "Best-practice / informational"),
    (["tabnabbing"], "Reverse tabnabbing"),
    (["autocomplete"], "Autocomplete enabled"),
    (["cookie flag", "secure flag", "httponly", "samesite"], "Missing cookie flags"),
    (["csrf"], "CSRF (login/logout or without impact)"),
    (["mixed content"], "Mixed content"),
    (["directory listing"], "Directory listing"),
]

_ALLOWED_VOCAB: List[Tuple[List[str], str]] = [
    (["manual testing", "manual review", "test manually", "by hand"], "manual"),
    (["automated", "automation", "scanners allowed", "you may use automated"], "automated"),
    (["authenticated"], "authenticated"),
    (["unauthenticated", "without authentication"], "unauthenticated"),
    (["api testing", "test the api", "api endpoints"], "api"),
    (["test account", "test accounts provided", "create an account"], "test accounts"),
]

_RED_FLAG_VOCAB: List[Tuple[List[str], str]] = [
    (["only manual", "manual testing only", "manual only", "no automated", "no automation",
      "no scanner", "no scanners", "without automated", "do not use automated",
      "automated tools are not", "automated tools are prohibited"],
     "Solo pruebas manuales / sin herramientas automatizadas"),
    (["contact before", "notify before", "prior approval", "request permission",
      "coordinate with", "email us before", "reach out before", "ask before"],
     "Requiere contacto / aprobación previa antes de probar"),
    (["test account", "request a test account", "use provided credentials"],
     "Requiere cuenta de prueba proporcionada"),
    (["vpn", "allowlist your ip", "whitelist your ip", "provide your ip"],
     "Requiere IP registrada / VPN"),
    (["do not test production", "staging only", "use the staging"],
     "Restringido a entorno de staging"),
]

_BOUNTY_VOCAB: List[Tuple[List[str], str]] = [
    (["bounty", "monetary", "cash", "usd", "$"], "Bounty monetario"),
    (["swag", "merch"], "Swag"),
    (["reputation", "kudos", "reconocimiento", "recognition", "hall of fame", "thanks"], "Reconocimiento / reputación"),
    (["first reporter", "first valid", "duplicates are not"], "Solo primer reporte válido"),
]

_REPORT_REQ_VOCAB: List[Tuple[List[str], str]] = [
    (["proof of concept", "poc", "steps to reproduce", "reproduction steps", "reproduce"], "PoC / pasos de reproducción obligatorios"),
    (["video", "screen recording"], "Vídeo requerido"),
    (["screenshot"], "Capturas de pantalla"),
    (["english", "in english"], "Reporte en inglés"),
    (["cvss"], "Puntuación CVSS requerida"),
    (["impact", "business impact"], "Descripción de impacto requerida"),
    (["template", "use our template", "report template"], "Formato/plantilla específico"),
]


# Cues that a fragment expresses a PROHIBITION (not a permission). Used to gate
# prohibited-action matches found in mixed sections like Rules of Engagement,
# so "automated testing is welcome" is never read as "automated is prohibited".
_PROHIBITION_CUES = (
    "do not", "don't", "not allowed", "not permitted", "prohibit", "forbidden",
    "never", "must not", "refrain", "avoid", "strictly", "no ", "without permission",
    "are not", "is not allowed", "disallow",
)


def _has_prohibition_cue(fragment: str) -> bool:
    low = fragment.lower()
    return any(cue in low for cue in _PROHIBITION_CUES)


def _match_vocab(fragments: List[str], vocab: List[Tuple[List[str], str]]) -> List[Dict[str, str]]:
    """Return [{value, source_quote}] for each vocab label present in *fragments*."""
    found: Dict[str, str] = {}
    for frag in fragments:
        low = f" {frag.lower()} "
        for needles, label in vocab:
            if label in found:
                continue
            if any(n in low for n in needles):
                found[label] = _clip(frag)
    return [{"value": lbl, "source_quote": q} for lbl, q in found.items()]


# ──────────────────────────────────────────────────────────────────────────
#  Field-specific heuristics
# ──────────────────────────────────────────────────────────────────────────
def _detect_severity_floor(sections: Dict[str, List[str]]) -> Dict[str, str]:
    frags = _fragments(
        sections.get("excluded", []) + sections.get("rewards", [])
        + sections.get("reporting_requirements", []) + sections.get("preamble", [])
    )
    # Explicit "minimum severity: medium".
    for frag in frags:
        m = re.search(r"minimum severity[^a-z]{0,4}(none|low|medium|high|critical)", frag, re.I)
        if m:
            return {"value": m.group(1).lower(), "source_quote": _clip(frag)}
    # "low (and below) not eligible/excluded" → floor above the mentioned level.
    for frag in frags:
        low = frag.lower()
        excl = any(k in low for k in ("not eligible", "excluded", "out of scope",
                                      "will not", "do not accept", "not accepted",
                                      "not rewarded", "no bounty"))
        if not excl:
            continue
        for level in ("low", "medium", "informational", "informative", "none"):
            if level in low:
                base = "none" if level in ("informational", "informative") else level
                idx = SEVERITY_ORDER.index(base) if base in SEVERITY_ORDER else 0
                floor = SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]
                return {"value": floor, "source_quote": _clip(frag)}
    return {"value": "", "source_quote": ""}


def _detect_rate_limits(sections: Dict[str, List[str]]) -> Dict[str, str]:
    frags = _fragments(
        sections.get("rules_of_engagement", []) + sections.get("preamble", [])
        + sections.get("in_scope", [])
    )
    for frag in frags:
        low = frag.lower()
        if "rate" in low or "request" in low or "rps" in low:
            m = re.search(r"(\d+)\s*(?:requests?|reqs?|calls?)?\s*(?:per|/)\s*(second|sec|s|minute|min|m|hour|h)", low)
            if m:
                return {"value": f"{m.group(1)} per {m.group(2)}", "source_quote": _clip(frag)}
            if "rate limit" in low or "rate-limit" in low or "rps" in low:
                return {"value": "declarado (sin número explícito)", "source_quote": _clip(frag)}
    return {"value": "", "source_quote": ""}


def _detect_window(sections: Dict[str, List[str]]) -> Dict[str, str]:
    frags = _fragments(
        sections.get("rules_of_engagement", []) + sections.get("preamble", [])
    )
    for frag in frags:
        low = frag.lower()
        if any(k in low for k in ("testing window", "business hours", "between",
                                  "utc", "time zone", "timezone", "off-hours",
                                  "outside of", "maintenance window")):
            if re.search(r"\d", frag) or "business hours" in low or "off-hours" in low:
                return {"value": _clip(frag), "source_quote": _clip(frag)}
    return {"value": "", "source_quote": ""}


# ──────────────────────────────────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────────────────────────────────
def parse_policy(
    handle: str,
    policy_md: str,
    *,
    out_of_scope_texts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Parse *policy_md* (plus optional structured-scope "Out of Scope" texts) into
    the actionable policy structure. Never touches the network.
    """
    policy_md = policy_md or ""
    sections = segment_sections(policy_md)
    # Fold structured-scope "Out of Scope" text into the out_of_scope section.
    if out_of_scope_texts:
        sections.setdefault("out_of_scope", [])
        sections["out_of_scope"].extend([str(t) for t in out_of_scope_texts if t])

    manual_reasons: List[str] = []

    def _need(section: str, label: str) -> None:
        if not sections.get(section):
            manual_reasons.append(f"no se encontró sección '{label}'")

    # Governing-section presence checks.
    _need("out_of_scope", "Out of Scope")
    _need("rules_of_engagement", "Rules of Engagement")
    _need("rewards", "Rewards")
    _need("reporting_requirements", "Reporting Requirements")

    # allowed_testing — STRICT: only from ROE / In-Scope (safe direction).
    allowed_frags = _fragments(
        sections.get("rules_of_engagement", []) + sections.get("in_scope", [])
    )
    allowed_testing = _match_vocab(allowed_frags, _ALLOWED_VOCAB)
    if not allowed_testing:
        manual_reasons.append("allowed_testing no explícito → deny-by-default (nada asumido como permitido)")

    # prohibited_actions — LIBERAL over inherently-prohibitive sections
    # (Prohibited / Out of Scope), but in Rules of Engagement (which mixes allow
    # and deny) only fragments carrying a prohibition cue count. This keeps a
    # permissive "automated testing is welcome" from becoming a false prohibition.
    prohibited_frags = _fragments(
        sections.get("prohibited", []) + sections.get("out_of_scope", [])
    )
    roe_prohibitive = [f for f in _fragments(sections.get("rules_of_engagement", []))
                       if _has_prohibition_cue(f)]
    prohibited_actions = _match_vocab(prohibited_frags + roe_prohibitive, _PROHIBITED_VOCAB)

    # excluded_vuln_classes — LIBERAL: excluded + out_of_scope.
    excluded_frags = _fragments(
        sections.get("excluded", []) + sections.get("out_of_scope", [])
    )
    excluded_vuln_classes = _match_vocab(excluded_frags, _EXCLUDED_VOCAB)

    severity_floor = _detect_severity_floor(sections)
    if not severity_floor["value"]:
        manual_reasons.append("severity_floor indeterminado → tratar conservadoramente")

    bounty_rules = _match_vocab(_fragments(sections.get("rewards", [])), _BOUNTY_VOCAB)
    report_requirements = _match_vocab(
        _fragments(sections.get("reporting_requirements", [])), _REPORT_REQ_VOCAB
    )
    rate_limits = _detect_rate_limits(sections)
    window = _detect_window(sections)

    # red_flags — scan every section (semantic markers, not section-bound).
    all_frags = _fragments([ln for lines in sections.values() for ln in lines])
    red_flags = _match_vocab(all_frags, _RED_FLAG_VOCAB)

    parsed: Dict[str, Any] = {
        "program": handle,
        "parsed_at": utc_now(),
        "sections_found": sorted(k for k in sections if k not in ("preamble", "other")),
        "allowed_testing": allowed_testing,
        "prohibited_actions": prohibited_actions,
        "excluded_vuln_classes": excluded_vuln_classes,
        "severity_floor": severity_floor,
        "bounty_eligibility_rules": bounty_rules,
        "report_requirements": report_requirements,
        "rate_limits_declarados": rate_limits,
        "window_de_testing": window,
        "red_flags": red_flags,
        "needs_manual_review": bool(manual_reasons),
        "manual_review_reasons": manual_reasons,
        "source_json_path": "",
    }
    return parsed


# ──────────────────────────────────────────────────────────────────────────
#  Convenience accessors + serialisation
# ──────────────────────────────────────────────────────────────────────────
def values(field: Any) -> List[str]:
    """Return just the labels from a [{value, source_quote}] field (or [])."""
    if isinstance(field, list):
        return [str(x.get("value", x)) if isinstance(x, dict) else str(x) for x in field]
    return []


def policy_to_csv_row(parsed: Dict[str, Any]) -> Dict[str, str]:
    """Flatten a parsed policy into a ``policies.csv`` row (JSON-string cells)."""
    import json

    def _dump(x: Any) -> str:
        return json.dumps(x, ensure_ascii=False)

    sev = parsed.get("severity_floor") or {}
    return {
        "program": parsed.get("program", ""),
        "parsed_at": parsed.get("parsed_at", utc_now()),
        "allowed_testing": _dump(parsed.get("allowed_testing", [])),
        "prohibited_actions": _dump(parsed.get("prohibited_actions", [])),
        "excluded_vuln_classes": _dump(parsed.get("excluded_vuln_classes", [])),
        "severity_floor": sev.get("value", "") if isinstance(sev, dict) else str(sev),
        "bounty_eligibility_rules": _dump(parsed.get("bounty_eligibility_rules", [])),
        "report_requirements": _dump(parsed.get("report_requirements", [])),
        "rate_limits_declarados": _dump(parsed.get("rate_limits_declarados", {})),
        "window_de_testing": _dump(parsed.get("window_de_testing", {})),
        "red_flags": _dump(parsed.get("red_flags", [])),
        "needs_manual_review": "true" if parsed.get("needs_manual_review") else "false",
        "source_json_path": parsed.get("source_json_path", ""),
    }


def load_policy_row(row: Dict[str, str]) -> Dict[str, Any]:
    """Inverse of :func:`policy_to_csv_row`: JSON-string cells → Python lists."""
    import json

    def _load(cell: str, default):
        try:
            return json.loads(cell) if cell else default
        except (ValueError, TypeError):
            return default

    return {
        "program": row.get("program", ""),
        "parsed_at": row.get("parsed_at", ""),
        "allowed_testing": _load(row.get("allowed_testing", ""), []),
        "prohibited_actions": _load(row.get("prohibited_actions", ""), []),
        "excluded_vuln_classes": _load(row.get("excluded_vuln_classes", ""), []),
        "severity_floor": {"value": row.get("severity_floor", ""), "source_quote": ""},
        "bounty_eligibility_rules": _load(row.get("bounty_eligibility_rules", ""), []),
        "report_requirements": _load(row.get("report_requirements", ""), []),
        "rate_limits_declarados": _load(row.get("rate_limits_declarados", ""), {}),
        "window_de_testing": _load(row.get("window_de_testing", ""), {}),
        "red_flags": _load(row.get("red_flags", ""), []),
        "needs_manual_review": str(row.get("needs_manual_review", "")).lower() == "true",
        "manual_review_reasons": [],
        "source_json_path": row.get("source_json_path", ""),
    }


def render_policy_md(parsed: Dict[str, Any], *, simulation: bool = False) -> str:
    """Human-readable Markdown view of a parsed policy (every claim quoted)."""
    tag = "  ·  **SIMULACIÓN**" if simulation else ""
    handle = parsed.get("program", "?")
    lines = [f"# Política parseada — `{handle}`{tag}", ""]
    if parsed.get("needs_manual_review"):
        lines += ["> ⚠️ **needs_manual_review = true**"]
        for r in parsed.get("manual_review_reasons", []):
            lines.append(f"> - {r}")
        lines.append("")
    lines += [
        f"- **Secciones detectadas:** {', '.join(parsed.get('sections_found', [])) or '—'}",
        f"- **Severity floor:** `{(parsed.get('severity_floor') or {}).get('value','') or 'indeterminado'}`",
        f"- **Rate limit declarado:** {(parsed.get('rate_limits_declarados') or {}).get('value','') or '—'}",
        f"- **Ventana de testing:** {(parsed.get('window_de_testing') or {}).get('value','') or '—'}",
        "",
    ]

    def _block(title: str, items: List[Dict[str, str]]) -> None:
        lines.append(f"## {title}")
        if not items:
            lines.append("_—_\n")
            return
        for it in items:
            if isinstance(it, dict):
                lines.append(f"- **{it.get('value','')}**  \n  > _cita:_ {it.get('source_quote','') or '—'}")
            else:
                lines.append(f"- {it}")
        lines.append("")

    _block("Testing permitido (allowed_testing)", parsed.get("allowed_testing", []))
    _block("Acciones prohibidas (prohibited_actions)", parsed.get("prohibited_actions", []))
    _block("Clases de vuln excluidas (excluded_vuln_classes)", parsed.get("excluded_vuln_classes", []))
    _block("Elegibilidad de bounty", parsed.get("bounty_eligibility_rules", []))
    _block("Requisitos de reporte", parsed.get("report_requirements", []))
    _block("Red flags", parsed.get("red_flags", []))
    return "\n".join(lines) + "\n"
