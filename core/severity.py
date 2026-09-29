"""
core.severity
=============

One canonical severity ordering for the whole pipeline, plus a couple of tiny
comparison helpers. Kept in its own module so the analyst layer (scoring,
planner, reportability) never re-implements the ``none < low < ... < critical``
scale in three subtly different ways.

The scale matches HackerOne's severity ratings and the ``severity_rating`` enum
in ``templates/finding.json``.
"""

from __future__ import annotations

from typing import Optional

# Lowest → highest. "" (unrated) is treated as the same rank as "none".
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def normalize_severity(value: str) -> str:
    """Fold aliases / casing to a canonical severity name; '' → 'none'."""
    if not value:
        return "none"
    v = str(value).strip().lower()
    aliases = {
        "informational": "none",
        "info": "none",
        "": "none",
        "crit": "critical",
        "med": "medium",
    }
    v = aliases.get(v, v)
    return v if v in _RANK else "none"


def severity_rank(value: str) -> int:
    """Integer rank on :data:`SEVERITY_ORDER` (unknown → 0 = none)."""
    return _RANK.get(normalize_severity(value), 0)


def meets_floor(severity: str, floor: Optional[str]) -> bool:
    """
    True when *severity* is at or above *floor*.

    An empty/unknown floor means "no declared floor" → nothing is filtered out
    by severity here (deny-by-default lives in the caller, which flags an
    unknown floor as needs_manual_review rather than silently passing).
    """
    if not floor:
        return True
    return severity_rank(severity) >= severity_rank(floor)
