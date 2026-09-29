"""
core.csvstore
=============

The ONLY module that is allowed to read or write CSV files under ``data/``.

Design goals
------------
* Single source of truth for every entity's columns (``SCHEMA``). Adding a
  field is a one-line change.
* Automatic file creation with the correct header the first time an entity
  is touched.
* Atomic writes: we always write to ``<file>.tmp`` and ``os.replace`` it over
  the target, so a crash mid-write can never leave a half-written CSV.
* All timestamps are ISO-8601 in UTC (see :func:`utc_now`).

This module is deliberately dependency-free (stdlib only).
"""

from __future__ import annotations

import csv
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# ──────────────────────────────────────────────────────────────────────────
#  Central schema. One entry per CSV entity.  <entity> -> ordered columns.
#  To add a column: append it here. csvstore migrates existing files on read.
# ──────────────────────────────────────────────────────────────────────────
SCHEMA: Dict[str, List[str]] = {
    "programs": [
        "handle", "name", "state", "bounty", "last_synced_at",
        # ── analyst layer (additive; migrated as "" on old files) ──
        "enabled", "policy_md",
    ],
    "scopes": [
        "program", "asset", "asset_type", "in_scope", "severity_max",
        "eligible_for_bounty", "eligible_for_submission", "notes",
    ],
    "assets": [
        "program", "asset", "resolved_ips", "technologies", "alive",
        "http_status", "first_seen", "last_seen",
    ],
    "findings": [
        "id", "program", "title", "severity", "cvss_vector", "cvss_score",
        "cwe", "asset", "status", "dedup_hash", "report_path",
        "created_at", "updated_at",
        # ── analyst layer: explicit vuln class powers reportability ──
        "vuln_class",
    ],
    "reports": [
        "id", "finding_id", "version", "path", "submitted_at",
        "h1_report_id", "state", "triaged_at", "bounty_amount",
    ],
    "sessions": [
        "id", "program", "agent", "started_at", "ended_at",
        "tools_used", "stats_json",
    ],
    "events": [
        "ts", "session_id", "agent", "level", "message", "payload_json",
    ],
    # ──────────────────────────────────────────────────────────────────
    #  Analyst / decision layer (added by the senior-analyst extension).
    # ──────────────────────────────────────────────────────────────────
    "policies": [
        "program", "parsed_at", "allowed_testing", "prohibited_actions",
        "excluded_vuln_classes", "severity_floor", "bounty_eligibility_rules",
        "report_requirements", "rate_limits_declarados", "window_de_testing",
        "red_flags", "needs_manual_review", "source_json_path",
    ],
    "plans": [
        "id", "program", "asset", "session_id", "created_at", "priority",
        "checks_count", "plan_path",
    ],
    "reportability": [
        "finding_id", "evaluated_at", "verdict", "reason", "priority",
        "policy_quote", "next_agent",
    ],
}

# Composite keys used by upsert() when the caller does not pass one.
DEFAULT_KEYS: Dict[str, List[str]] = {
    "programs": ["handle"],
    "scopes": ["program", "asset"],
    "assets": ["program", "asset"],
    "findings": ["id"],
    "reports": ["id"],
    "sessions": ["id"],
    "events": [],  # append-only, never upserted
    # Analyst layer.
    "policies": ["program"],
    "plans": ["id"],
    "reportability": ["finding_id"],
}

# Default data directory. Overridable via CSVStore(data_dir=...).
DEFAULT_DATA_DIR = Path(
    os.environ.get("VDP_DATA_DIR", "data")
)


def utc_now() -> str:
    """Return the current time as an ISO-8601 UTC string (seconds precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value: str) -> Optional[datetime]:
    """
    Parse an ISO-8601 timestamp produced by :func:`utc_now` (or a plain date)
    into a timezone-aware ``datetime`` in UTC. Returns ``None`` on any failure
    or empty input, so callers can treat "unparseable" as "unknown".
    """
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # Tolerate a trailing "Z" (some producers use it instead of +00:00).
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        # Last resort: a bare date (YYYY-MM-DD).
        try:
            dt = datetime.strptime(raw[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def days_since(value: str, now: Optional[datetime] = None) -> Optional[float]:
    """
    Whole/fractional days between an ISO timestamp and *now* (UTC).

    Returns ``None`` when the input cannot be parsed, so "never happened" and
    "cannot tell" are distinguishable from a real ``0``.
    """
    dt = parse_iso(value)
    if dt is None:
        return None
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    return (ref - dt).total_seconds() / 86400.0


class CSVStore:
    """Thin, atomic, schema-aware CSV persistence layer."""

    def __init__(self, data_dir: os.PathLike | str = DEFAULT_DATA_DIR) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    # ── internals ────────────────────────────────────────────────────────
    def _path(self, entity: str) -> Path:
        if entity not in SCHEMA:
            raise KeyError(f"Unknown entity '{entity}'. Known: {list(SCHEMA)}")
        return self.data_dir / f"{entity}.csv"

    def _ensure(self, entity: str) -> Path:
        """Create the CSV with its header if it does not yet exist."""
        path = self._path(entity)
        if not path.exists():
            self._atomic_write(entity, rows=[])
        return path

    def _atomic_write(self, entity: str, rows: List[Dict[str, str]]) -> None:
        """Write *all* rows for an entity atomically (tmp file + os.replace)."""
        cols = SCHEMA[entity]
        path = self._path(entity)
        path.parent.mkdir(parents=True, exist_ok=True)
        # NamedTemporaryFile in the same dir so os.replace is atomic (same fs).
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{entity}.", suffix=".tmp", dir=str(path.parent)
        )
        try:
            with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    # Normalise: fill missing cols, stringify everything.
                    writer.writerow({c: _cell(row.get(c, "")) for c in cols})
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)  # atomic on POSIX
        except BaseException:
            # Clean up the temp file on any failure.
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # ── public API ───────────────────────────────────────────────────────
    def read_all(self, entity: str) -> List[Dict[str, str]]:
        """Return every row of *entity* as a list of dicts (header-aligned)."""
        path = self._ensure(entity)
        cols = SCHEMA[entity]
        out: List[Dict[str, str]] = []
        with path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for raw in reader:
                # Migrate/align to the current schema (new cols -> "").
                out.append({c: (raw.get(c) or "") for c in cols})
        return out

    def append(self, entity: str, row: Dict[str, str]) -> Dict[str, str]:
        """Append a single row. Fast path that does not rewrite the file."""
        path = self._ensure(entity)
        cols = SCHEMA[entity]
        normalised = {c: _cell(row.get(c, "")) for c in cols}
        # Append is inherently not atomic across the whole file, but a single
        # row append is a single write; to stay crash-safe we still funnel
        # through a full atomic rewrite when the row count is small enough is
        # overkill, so we append directly with an fsync.
        with path.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            writer.writerow(normalised)
            fh.flush()
            os.fsync(fh.fileno())
        return normalised

    def upsert(
        self,
        entity: str,
        row: Dict[str, str],
        key: Optional[Iterable[str]] = None,
    ) -> Dict[str, str]:
        """
        Insert *row*, or update the existing row matching the composite *key*.

        Returns the stored row. Rewrites the whole file atomically.
        """
        key_cols = list(key) if key is not None else DEFAULT_KEYS.get(entity, [])
        if not key_cols:
            # No key -> behave like append.
            return self.append(entity, row)

        rows = self.read_all(entity)
        cols = SCHEMA[entity]
        candidate = {c: _cell(row.get(c, "")) for c in cols}
        key_tuple = tuple(candidate.get(k, "") for k in key_cols)

        found = False
        for i, existing in enumerate(rows):
            if tuple(existing.get(k, "") for k in key_cols) == key_tuple:
                # Merge: only overwrite columns the caller actually provided.
                merged = dict(existing)
                for c in cols:
                    if c in row and row[c] is not None and row[c] != "":
                        merged[c] = _cell(row[c])
                rows[i] = merged
                candidate = merged
                found = True
                break
        if not found:
            rows.append(candidate)

        self._atomic_write(entity, rows)
        return candidate

    def next_id(self, entity: str, column: str = "id") -> int:
        """Return the next integer id (max existing + 1, or 1 if empty)."""
        rows = self.read_all(entity)
        max_id = 0
        for r in rows:
            try:
                max_id = max(max_id, int(r.get(column, "0") or 0))
            except (ValueError, TypeError):
                continue
        return max_id + 1


def _cell(value) -> str:
    """Coerce any value into a CSV-safe string. None -> ''."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
