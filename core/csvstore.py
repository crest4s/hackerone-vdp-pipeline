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
}

# Default data directory. Overridable via CSVStore(data_dir=...).
DEFAULT_DATA_DIR = Path(
    os.environ.get("VDP_DATA_DIR", "data")
)


def utc_now() -> str:
    """Return the current time as an ISO-8601 UTC string (seconds precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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
