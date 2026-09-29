"""
core.scope
==========

Scope validation engine. Given a program's structured scope (as synced into
``workspace/scope/<handle>.json`` or ``data/scopes.csv``) and a target, decide
whether the target is authorized.

Rules (deny-by-default):
  * A wildcard ``*.example.com`` authorizes any subdomain, but NOT the apex
    ``example.com`` itself (unless the apex is listed separately).
  * A specific exclusion (an out-of-scope entry) ALWAYS wins over a wildcard
    inclusion.
  * IP and IP/CIDR assets are matched by address/network containment.
  * On any ambiguity or parse failure: DENY.

The result is a small dataclass so callers can log the reason.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


@dataclass
class ScopeDecision:
    allowed: bool
    target: str
    reason: str
    matched_asset: str = ""
    program: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:  # truthy iff allowed
        return self.allowed


# ──────────────────────────────────────────────────────────────────────────
#  Target extraction helpers
# ──────────────────────────────────────────────────────────────────────────
def extract_host(target: str) -> str:
    """Return a bare host/ip from a URL or host string (lower-cased)."""
    t = target.strip()
    if "://" in t:
        t = urlsplit(t).hostname or ""
    else:
        # Strip any path/port a bare "host:port/path" might carry.
        t = t.split("/")[0]
        if t.count(":") == 1:  # host:port (not an IPv6 literal)
            t = t.split(":")[0]
    return t.lower().rstrip(".")


def _as_network(value: str):
    """Return an ip_network if value looks like an IP/CIDR, else None."""
    try:
        v = value.strip()
        if "/" in v:
            return ipaddress.ip_network(v, strict=False)
        return ipaddress.ip_network(f"{v}/32" if ":" not in v else f"{v}/128", strict=False)
    except ValueError:
        return None


def _host_matches_asset(host: str, asset: str) -> bool:
    """Match a host against a single scope asset pattern (domain semantics)."""
    asset = asset.strip().lower().rstrip(".")
    if not asset or not host:
        return False

    # Strip an explicit scheme/path from the asset identifier if present.
    if "://" in asset:
        asset = urlsplit(asset).hostname or asset
    asset = asset.split("/")[0]

    # Wildcard: "*.example.com" -> any subdomain, NOT the apex.
    if asset.startswith("*."):
        base = asset[2:]
        return host != base and host.endswith("." + base)

    # Bare domain: exact host, OR a subdomain of it is NOT implied.
    # Exact match only (apex). Subdomain inclusion requires an explicit wildcard.
    return host == asset


def _ip_matches_asset(host: str, asset: str) -> bool:
    net = _as_network(asset)
    if net is None:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr in net


# ──────────────────────────────────────────────────────────────────────────
#  Scope loading
# ──────────────────────────────────────────────────────────────────────────
def load_scope_json(path: Path) -> List[Dict[str, Any]]:
    """Load a synced structured-scope JSON file (list of scope objects)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("data", data.get("scopes", []))
    return list(data or [])


def _scope_entries(scopes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalise heterogeneous scope objects into a flat list of:
        {asset, in_scope(bool), asset_type}
    Accepts both raw H1 JSON:API objects and our own csv-style dicts.
    """
    out: List[Dict[str, Any]] = []
    for s in scopes:
        attrs = s.get("attributes", s)  # H1 nests under "attributes"
        asset = (
            attrs.get("asset_identifier")
            or attrs.get("asset")
            or attrs.get("identifier")
            or ""
        )
        if not asset:
            continue
        in_scope = attrs.get("eligible_for_submission")
        if in_scope is None:
            in_scope = attrs.get("in_scope")
        if isinstance(in_scope, str):
            in_scope = in_scope.strip().lower() in ("true", "1", "yes")
        out.append(
            {
                "asset": str(asset),
                "in_scope": bool(in_scope) if in_scope is not None else True,
                "asset_type": attrs.get("asset_type", ""),
            }
        )
    return out


# ──────────────────────────────────────────────────────────────────────────
#  Core decision
# ──────────────────────────────────────────────────────────────────────────
def validate(target: str, scopes: List[Dict[str, Any]], program: str = "") -> ScopeDecision:
    """
    Decide whether *target* is in scope for the given normalized scope list.

    Exclusions win over inclusions; wildcards never cover their apex; deny by
    default.
    """
    host = extract_host(target)
    if not host:
        return ScopeDecision(False, target, "could not extract a host from target", program=program)

    entries = _scope_entries(scopes)
    if not entries:
        return ScopeDecision(False, target, "no scope entries loaded (deny-by-default)", program=program)

    excluded = [e for e in entries if not e["in_scope"]]
    included = [e for e in entries if e["in_scope"]]

    # 1) Explicit exclusions always win.
    for e in excluded:
        if _host_matches_asset(host, e["asset"]) or _ip_matches_asset(host, e["asset"]):
            return ScopeDecision(
                False, target,
                f"target matches an explicit OUT-OF-SCOPE entry: {e['asset']}",
                matched_asset=e["asset"], program=program,
            )

    # 2) Inclusions.
    for e in included:
        if _host_matches_asset(host, e["asset"]) or _ip_matches_asset(host, e["asset"]):
            return ScopeDecision(
                True, target,
                f"target authorized by in-scope entry: {e['asset']}",
                matched_asset=e["asset"], program=program,
            )

    # 3) Deny by default.
    return ScopeDecision(
        False, target, "target does not match any in-scope entry (deny-by-default)",
        program=program,
    )


def validate_from_file(target: str, scope_file: Path, program: str = "") -> ScopeDecision:
    """Convenience wrapper: load a scope JSON file and validate a target."""
    try:
        scopes = load_scope_json(scope_file)
    except (OSError, json.JSONDecodeError) as exc:
        return ScopeDecision(False, target, f"failed to load scope file: {exc}", program=program)
    return validate(target, scopes, program=program)
