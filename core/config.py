"""
core.config
===========

Loads YAML configuration (``config/config.yaml`` and
``config/programs.yaml``) and environment secrets (``.env``).

Secrets are read from environment variables ONLY. Nothing here ever holds a
default token value; a missing credential raises a clear error at call time,
not import time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    from dotenv import load_dotenv
except ImportError:  # dotenv is optional; env vars still work without it.
    def load_dotenv(*_a, **_k):  # type: ignore
        return False


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


class ConfigError(RuntimeError):
    """Raised for missing/invalid configuration or credentials."""


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into a copy of *base*."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


@dataclass
class Credentials:
    username: str
    token: str


class Config:
    """Parsed, merged view over the pipeline configuration."""

    def __init__(self, config_dir: Path = CONFIG_DIR) -> None:
        self.config_dir = Path(config_dir)
        load_dotenv(PROJECT_ROOT / ".env")  # no-op if the file is absent
        self._config = self._load_yaml("config.yaml")
        self._programs = self._load_yaml("programs.yaml")

    # ── loading ──────────────────────────────────────────────────────────
    def _load_yaml(self, name: str) -> Dict[str, Any]:
        path = self.config_dir / name
        if not path.exists():
            raise ConfigError(f"Missing config file: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{path} must contain a YAML mapping at the top level")
        return data

    # ── generic access ───────────────────────────────────────────────────
    def get(self, *keys: str, default: Any = None) -> Any:
        """Nested lookup: cfg.get('nuclei', 'rate_limit')."""
        node: Any = self._config
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    @property
    def raw(self) -> Dict[str, Any]:
        return self._config

    # ── programs ─────────────────────────────────────────────────────────
    def programs(self) -> List[Dict[str, Any]]:
        return list(self._programs.get("programs", []))

    def program(self, handle: str) -> Optional[Dict[str, Any]]:
        for p in self.programs():
            if p.get("handle") == handle:
                return p
        return None

    def is_enabled(self, handle: str) -> bool:
        p = self.program(handle)
        return bool(p and p.get("enabled") is True)

    def effective_config(self, handle: str) -> Dict[str, Any]:
        """config.yaml with the program's `overrides` block merged in."""
        p = self.program(handle) or {}
        return _deep_merge(self._config, p.get("overrides", {}))

    # ── credentials (env only) ───────────────────────────────────────────
    def credentials(self) -> Credentials:
        user = os.environ.get("H1_USERNAME")
        token = os.environ.get("H1_API_TOKEN")
        missing = [
            n for n, v in (("H1_USERNAME", user), ("H1_API_TOKEN", token)) if not v
        ]
        if missing:
            raise ConfigError(
                "Missing HackerOne credentials in environment: "
                + ", ".join(missing)
                + ". Copy .env.example to .env and fill it in, or export them."
            )
        return Credentials(username=user, token=token)  # type: ignore[arg-type]

    # ── convenience path helpers ─────────────────────────────────────────
    def path(self, key: str) -> Path:
        rel = self.get("paths", key, default=key)
        p = Path(rel)
        return p if p.is_absolute() else (PROJECT_ROOT / p)


# Module-level singleton for convenience.
_default: Optional[Config] = None


def load() -> Config:
    global _default
    if _default is None:
        _default = Config()
    return _default
