"""
core.logger
===========

Structured, dual-sink logging:

  1. A JSONL line appended to ``workspace/logs/<YYYY-MM-DD>.jsonl`` (raw
     evidence, one event per line, machine-parseable).
  2. A row appended to ``data/events.csv`` (queryable history via csvstore).

Every event carries a UTC timestamp, an optional session id, the emitting
agent, a level, a message and an arbitrary JSON payload.

The logger never raises on a logging failure: observability must not take the
pipeline down. Failures are best-effort printed to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .csvstore import CSVStore, utc_now

VALID_LEVELS = ("debug", "info", "warning", "error", "critical")


class Logger:
    def __init__(
        self,
        logs_dir: os.PathLike | str = "workspace/logs",
        store: Optional[CSVStore] = None,
        session_id: str = "",
        agent: str = "system",
    ) -> None:
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.store = store or CSVStore()
        self.session_id = session_id
        self.agent = agent

    def _jsonl_path(self) -> Path:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.logs_dir / f"{day}.jsonl"

    def log(
        self,
        message: str,
        level: str = "info",
        payload: Optional[Dict[str, Any]] = None,
        *,
        agent: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        level = level.lower()
        if level not in VALID_LEVELS:
            level = "info"
        event = {
            "ts": utc_now(),
            "session_id": session_id if session_id is not None else self.session_id,
            "agent": agent or self.agent,
            "level": level,
            "message": message,
            "payload": payload or {},
        }
        self._write_jsonl(event)
        self._write_csv(event)
        return event

    # ── sinks (best-effort, never raise) ─────────────────────────────────
    def _write_jsonl(self, event: Dict[str, Any]) -> None:
        try:
            line = json.dumps(event, ensure_ascii=False, sort_keys=True)
            with self._jsonl_path().open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception as exc:  # noqa: BLE001 - logging must not crash callers
            print(f"[logger] JSONL write failed: {exc}", file=sys.stderr)

    def _write_csv(self, event: Dict[str, Any]) -> None:
        try:
            self.store.append(
                "events",
                {
                    "ts": event["ts"],
                    "session_id": event["session_id"],
                    "agent": event["agent"],
                    "level": event["level"],
                    "message": event["message"],
                    "payload_json": json.dumps(event["payload"], ensure_ascii=False),
                },
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[logger] events.csv write failed: {exc}", file=sys.stderr)

    # ── convenience shortcuts ────────────────────────────────────────────
    def debug(self, msg: str, **kw: Any) -> Dict[str, Any]:
        return self.log(msg, "debug", kw or None)

    def info(self, msg: str, **kw: Any) -> Dict[str, Any]:
        return self.log(msg, "info", kw or None)

    def warning(self, msg: str, **kw: Any) -> Dict[str, Any]:
        return self.log(msg, "warning", kw or None)

    def error(self, msg: str, **kw: Any) -> Dict[str, Any]:
        return self.log(msg, "error", kw or None)


def get_logger(session_id: str = "", agent: str = "system") -> Logger:
    return Logger(session_id=session_id, agent=agent)
