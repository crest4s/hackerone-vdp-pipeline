"""
core.store
==========

High-level history API built on top of :mod:`core.csvstore`.

Callers (scripts, agents) use these functions instead of touching CSV columns
directly. Finding deduplication uses a stable SHA-256 hash so the same
vulnerability on the same endpoint never produces two records:

    dedup_hash = sha256("program|asset|vuln_class|normalized_endpoint")

Endpoint normalization lower-cases the host, strips default ports, drops the
fragment and trailing slash, and sorts query keys so cosmetic differences do
not defeat dedup.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .csvstore import CSVStore, utc_now


# ──────────────────────────────────────────────────────────────────────────
#  Endpoint normalization + dedup hashing
# ──────────────────────────────────────────────────────────────────────────
def normalize_endpoint(endpoint: str) -> str:
    """Return a canonical form of an endpoint/URL for stable hashing."""
    if not endpoint:
        return ""
    raw = endpoint.strip()
    # Add a scheme if missing so urlsplit parses host correctly.
    parsed = urlsplit(raw if "://" in raw else f"http://{raw}")
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    # Drop default ports.
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parsed.path.rstrip("/") or "/"
    # Sort query params for stability; drop the fragment entirely.
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def dedup_hash(program: str, asset: str, vuln_class: str, endpoint: str) -> str:
    """Stable SHA-256 dedup hash for a finding."""
    basis = "|".join(
        [
            (program or "").strip().lower(),
            (asset or "").strip().lower(),
            (vuln_class or "").strip().lower(),
            normalize_endpoint(endpoint),
        ]
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class Store:
    """Domain-level persistence API."""

    def __init__(self, csv: Optional[CSVStore] = None) -> None:
        self.csv = csv or CSVStore()

    # ── programs ─────────────────────────────────────────────────────────
    def upsert_program(
        self,
        handle: str,
        name: str = "",
        state: str = "",
        bounty: str = "",
        *,
        enabled: Optional[bool] = None,
        policy_md: str = "",
    ) -> Dict[str, str]:
        row: Dict[str, Any] = {
            "handle": handle,
            "name": name,
            "state": state,
            "bounty": bounty,
            "last_synced_at": utc_now(),
        }
        # Only overwrite the analyst-layer columns when the caller supplies
        # them, so a plain re-sync never clobbers a policy captured earlier.
        if enabled is not None:
            row["enabled"] = bool(enabled)
        if policy_md:
            row["policy_md"] = policy_md
        return self.csv.upsert("programs", row, key=["handle"])

    def get_program(self, handle: str) -> Optional[Dict[str, str]]:
        for row in self.csv.read_all("programs"):
            if row.get("handle") == handle:
                return row
        return None

    def list_programs(self) -> List[Dict[str, str]]:
        return self.csv.read_all("programs")

    # ── scopes ───────────────────────────────────────────────────────────
    def upsert_scope(self, program: str, asset: str, **fields: Any) -> Dict[str, str]:
        row = {"program": program, "asset": asset}
        row.update({k: v for k, v in fields.items()})
        return self.csv.upsert("scopes", row, key=["program", "asset"])

    def get_scopes(self, program: Optional[str] = None) -> List[Dict[str, str]]:
        rows = self.csv.read_all("scopes")
        if program is None:
            return rows
        return [r for r in rows if r.get("program") == program]

    # ── assets ───────────────────────────────────────────────────────────
    def upsert_asset(self, program: str, asset: str, **fields: Any) -> Dict[str, str]:
        now = utc_now()
        existing = None
        for r in self.csv.read_all("assets"):
            if r.get("program") == program and r.get("asset") == asset:
                existing = r
                break
        row = {"program": program, "asset": asset, "last_seen": now}
        if existing is None:
            row["first_seen"] = now
        row.update(fields)
        return self.csv.upsert("assets", row, key=["program", "asset"])

    # ── findings ─────────────────────────────────────────────────────────
    def create_finding(
        self,
        program: str,
        title: str,
        asset: str,
        vuln_class: str,
        endpoint: str,
        *,
        severity: str = "",
        cvss_vector: str = "",
        cvss_score: str = "",
        cwe: str = "",
        status: str = "new",
        report_path: str = "",
    ) -> Dict[str, str]:
        """
        Create a finding, or return the existing one if the dedup hash matches.

        Dedup is by sha256(program|asset|vuln_class|normalized_endpoint).
        """
        dh = dedup_hash(program, asset, vuln_class, endpoint)
        for r in self.csv.read_all("findings"):
            if r.get("dedup_hash") == dh:
                return r  # duplicate: return the original, do not insert.

        now = utc_now()
        fid = str(self.csv.next_id("findings"))
        row = {
            "id": fid,
            "program": program,
            "title": title,
            "severity": severity,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "cwe": cwe,
            "asset": asset,
            "status": status,
            "dedup_hash": dh,
            "report_path": report_path,
            "created_at": now,
            "updated_at": now,
            # Persist the vuln class explicitly so reportability can match it
            # against a program's excluded_vuln_classes without re-parsing the
            # title. The dedup hash is unchanged, so dedup behaviour is intact.
            "vuln_class": vuln_class,
        }
        return self.csv.upsert("findings", row, key=["id"])

    def update_finding_status(
        self, finding_id: str, status: str, **fields: Any
    ) -> Optional[Dict[str, str]]:
        row = {"id": str(finding_id), "status": status, "updated_at": utc_now()}
        row.update(fields)
        # Only upsert if the finding exists.
        if not any(r.get("id") == str(finding_id) for r in self.csv.read_all("findings")):
            return None
        return self.csv.upsert("findings", row, key=["id"])

    def list_findings(
        self, program: Optional[str] = None, status: Optional[str] = None
    ) -> List[Dict[str, str]]:
        rows = self.csv.read_all("findings")
        if program is not None:
            rows = [r for r in rows if r.get("program") == program]
        if status is not None:
            rows = [r for r in rows if r.get("status") == status]
        return rows

    # ── reports ──────────────────────────────────────────────────────────
    def create_report(
        self,
        finding_id: str,
        path: str,
        *,
        version: int = 1,
        state: str = "draft",
        h1_report_id: str = "",
        bounty_amount: str = "",
    ) -> Dict[str, str]:
        rid = str(self.csv.next_id("reports"))
        row = {
            "id": rid,
            "finding_id": str(finding_id),
            "version": str(version),
            "path": path,
            "submitted_at": "",
            "h1_report_id": h1_report_id,
            "state": state,
            "triaged_at": "",
            "bounty_amount": bounty_amount,
        }
        return self.csv.upsert("reports", row, key=["id"])

    def list_reports(self, state: Optional[str] = None) -> List[Dict[str, str]]:
        rows = self.csv.read_all("reports")
        if state is not None:
            rows = [r for r in rows if r.get("state") == state]
        return rows

    # ── sessions & events ────────────────────────────────────────────────
    def start_session(
        self, program: str, agent: str, tools_used: str = "", stats: Optional[Dict] = None
    ) -> Dict[str, str]:
        sid = str(self.csv.next_id("sessions"))
        row = {
            "id": sid,
            "program": program,
            "agent": agent,
            "started_at": utc_now(),
            "ended_at": "",
            "tools_used": tools_used,
            "stats_json": json.dumps(stats or {}, ensure_ascii=False),
        }
        return self.csv.upsert("sessions", row, key=["id"])

    def end_session(self, session_id: str, stats: Optional[Dict] = None) -> Optional[Dict[str, str]]:
        row: Dict[str, Any] = {"id": str(session_id), "ended_at": utc_now()}
        if stats is not None:
            row["stats_json"] = json.dumps(stats, ensure_ascii=False)
        if not any(r.get("id") == str(session_id) for r in self.csv.read_all("sessions")):
            return None
        return self.csv.upsert("sessions", row, key=["id"])

    def add_event(
        self,
        session_id: str,
        agent: str,
        level: str,
        message: str,
        payload: Optional[Dict] = None,
    ) -> Dict[str, str]:
        return self.csv.append(
            "events",
            {
                "ts": utc_now(),
                "session_id": str(session_id),
                "agent": agent,
                "level": level,
                "message": message,
                "payload_json": json.dumps(payload or {}, ensure_ascii=False),
            },
        )

    # ── policies (parsed program policy, key: program) ───────────────────
    def upsert_policy(self, program: str, **fields: Any) -> Dict[str, str]:
        """
        Upsert the parsed policy for a program. List/dict fields are stored as
        JSON strings so the CSV stays a single flat cell per column.
        """
        row: Dict[str, Any] = {"program": program, "parsed_at": utc_now()}
        for key, value in fields.items():
            row[key] = _jsonify(value)
        return self.csv.upsert("policies", row, key=["program"])

    def get_policy(self, program: str) -> Optional[Dict[str, str]]:
        for row in self.csv.read_all("policies"):
            if row.get("program") == program:
                return row
        return None

    def list_policies(self) -> List[Dict[str, str]]:
        return self.csv.read_all("policies")

    # ── plans (attack plan per asset, key: id) ───────────────────────────
    def create_plan(
        self,
        program: str,
        asset: str,
        *,
        session_id: str = "",
        priority: str = "",
        checks_count: int = 0,
        plan_path: str = "",
    ) -> Dict[str, str]:
        pid = str(self.csv.next_id("plans"))
        row = {
            "id": pid,
            "program": program,
            "asset": asset,
            "session_id": session_id,
            "created_at": utc_now(),
            "priority": priority,
            "checks_count": str(checks_count),
            "plan_path": plan_path,
        }
        return self.csv.upsert("plans", row, key=["id"])

    def list_plans(self, program: Optional[str] = None) -> List[Dict[str, str]]:
        rows = self.csv.read_all("plans")
        if program is not None:
            rows = [r for r in rows if r.get("program") == program]
        return rows

    # ── reportability (verdict per finding, key: finding_id) ─────────────
    def upsert_reportability(
        self,
        finding_id: str,
        *,
        verdict: str,
        reason: str = "",
        priority: str = "",
        policy_quote: str = "",
        next_agent: str = "",
    ) -> Dict[str, str]:
        row = {
            "finding_id": str(finding_id),
            "evaluated_at": utc_now(),
            "verdict": verdict,
            "reason": reason,
            "priority": priority,
            "policy_quote": policy_quote,
            "next_agent": next_agent,
        }
        return self.csv.upsert("reportability", row, key=["finding_id"])

    def list_reportability(self) -> List[Dict[str, str]]:
        return self.csv.read_all("reportability")


def _jsonify(value: Any) -> str:
    """Serialise lists/dicts to compact JSON; pass scalars through as strings."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)
