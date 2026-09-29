"""
core.h1_api
===========

Robust client for the official HackerOne REST API (v1).

Highlights
----------
* HTTP Basic auth using ``H1_USERNAME`` + ``H1_API_TOKEN`` from the
  environment (never hardcoded).
* Transparent pagination via generators.
* Exponential backoff with jitter on 429 and transient 5xx errors, honouring
  a ``Retry-After`` header when present.
* Client-side rate limiting so we stay a polite API citizen.
* Read methods for programs, structured scopes and my reports.
* ``prepare_submission`` builds a valid report payload but DOES NOT send it
  unless ``dry_run`` is explicitly disabled AND the caller passes
  ``confirm=True``. Submission is a human-in-the-loop action by design.

Only the stdlib + ``requests`` are used.
"""

from __future__ import annotations

import base64
import random
import time
from typing import Any, Dict, Iterator, List, Optional

import requests


class H1APIError(RuntimeError):
    """Raised for non-retryable API errors or exhausted retries."""


class HackerOneClient:
    def __init__(
        self,
        username: str,
        token: str,
        *,
        base_url: str = "https://api.hackerone.com/v1/",
        user_agent: str = "vdp-pipeline/1.0 (+authorized-research)",
        rate_limit_rps: float = 2.0,
        max_retries: int = 5,
        backoff_base_seconds: float = 1.0,
        timeout: float = 30.0,
        dry_run_submit: bool = True,
    ) -> None:
        if not username or not token:
            raise H1APIError("HackerOne username and token are required (env vars).")
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.max_retries = max_retries
        self.backoff_base = backoff_base_seconds
        self.timeout = timeout
        self.dry_run_submit = dry_run_submit
        self._min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self._last_request = 0.0

        self.session = requests.Session()
        basic = base64.b64encode(f"{username}:{token}".encode()).decode()
        self.session.headers.update(
            {
                "Authorization": f"Basic {basic}",
                "Accept": "application/json",
                "User-Agent": user_agent,
            }
        )

    # ── low-level request with throttle + retry/backoff ──────────────────
    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        wait = self._min_interval - elapsed
        if wait > 0:
            time.sleep(wait)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = path if path.startswith("http") else self.base_url + path.lstrip("/")
        last_exc: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body, timeout=self.timeout
                )
                self._last_request = time.monotonic()
            except requests.RequestException as exc:
                last_exc = exc
                self._sleep_backoff(attempt)
                continue

            # Retryable status codes.
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                retry_after = resp.headers.get("Retry-After")
                if attempt < self.max_retries:
                    self._sleep_backoff(attempt, retry_after)
                    continue
                raise H1APIError(
                    f"{method} {url} failed after {self.max_retries} retries "
                    f"(HTTP {resp.status_code})"
                )

            if resp.status_code == 401:
                raise H1APIError("HTTP 401 Unauthorized: check H1_USERNAME / H1_API_TOKEN.")
            if resp.status_code == 403:
                raise H1APIError(f"HTTP 403 Forbidden for {url}: insufficient scope/permission.")
            if resp.status_code >= 400:
                raise H1APIError(f"{method} {url} -> HTTP {resp.status_code}: {resp.text[:400]}")

            if not resp.content:
                return {}
            try:
                return resp.json()
            except ValueError as exc:
                raise H1APIError(f"Invalid JSON from {url}: {exc}") from exc

        raise H1APIError(f"{method} {url} failed: {last_exc}")

    def _sleep_backoff(self, attempt: int, retry_after: Optional[str] = None) -> None:
        if retry_after:
            try:
                time.sleep(min(float(retry_after), 120.0))
                return
            except (ValueError, TypeError):
                pass
        # Exponential backoff with full jitter.
        base = self.backoff_base * (2 ** attempt)
        time.sleep(min(base + random.uniform(0, base), 120.0))

    # ── pagination helper ────────────────────────────────────────────────
    def _paginate(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        """Yield every ``data`` item across all pages, following JSON:API links."""
        next_url: Optional[str] = None
        page_params = dict(params or {})
        page_params.setdefault("page[size]", 100)

        first = True
        while True:
            if first:
                payload = self._request("GET", path, params=page_params)
                first = False
            elif next_url:
                payload = self._request("GET", next_url)
            else:
                break

            for item in payload.get("data", []) or []:
                yield item

            links = payload.get("links", {}) or {}
            next_url = links.get("next")
            if not next_url:
                break

    # ── read methods ─────────────────────────────────────────────────────
    def list_programs(self) -> Iterator[Dict[str, Any]]:
        """Yield every program the authenticated account can access."""
        yield from self._paginate("me/programs")

    def get_program(self, handle: str) -> Dict[str, Any]:
        """Fetch a single program by handle."""
        return self._request("GET", f"programs/{handle}")

    def get_structured_scopes(self, handle: str) -> List[Dict[str, Any]]:
        """Return the structured scope objects for a program."""
        return list(self._paginate(f"programs/{handle}/structured_scopes"))

    def list_my_reports(self, **filters: Any) -> Iterator[Dict[str, Any]]:
        """Yield the authenticated researcher's reports (optionally filtered)."""
        params: Dict[str, Any] = {}
        for k, v in filters.items():
            params[f"filter[{k}]"] = v
        yield from self._paginate("me/reports", params=params)

    def get_report(self, report_id: str) -> Dict[str, Any]:
        """Fetch a single report by id."""
        return self._request("GET", f"reports/{report_id}")

    # ── submission (guarded, human-in-the-loop) ──────────────────────────
    def prepare_submission(
        self,
        program_handle: str,
        title: str,
        vulnerability_information: str,
        severity_rating: str = "none",
        *,
        weakness_id: Optional[int] = None,
        impact: str = "",
    ) -> Dict[str, Any]:
        """
        Build (but do not send) a JSON:API report-creation payload.

        Returns the exact body that *would* be POSTed. Sending is deliberately
        a separate, confirmed action (see :meth:`submit`).
        """
        attributes: Dict[str, Any] = {
            "team_handle": program_handle,
            "title": title,
            "vulnerability_information": vulnerability_information,
            "severity_rating": severity_rating,
        }
        if impact:
            attributes["impact"] = impact
        if weakness_id is not None:
            attributes["weakness_id"] = weakness_id
        return {"data": {"type": "report", "attributes": attributes}}

    def submit(self, payload: Dict[str, Any], *, confirm: bool = False) -> Dict[str, Any]:
        """
        Submit a prepared report payload to HackerOne.

        Guarded twice:
          * ``dry_run_submit`` must be False (config), AND
          * ``confirm`` must be True (explicit at the call site).

        Otherwise this is a no-op that returns a ``{"dry_run": True, ...}``
        envelope so the caller can log the intended action.
        """
        if self.dry_run_submit or not confirm:
            return {
                "dry_run": True,
                "reason": "submission blocked by dry_run/confirm guard",
                "would_send": payload,
            }
        return self._request("POST", "reports", json_body=payload)


def from_config(cfg) -> "HackerOneClient":
    """Build a client from a :class:`core.config.Config` instance."""
    creds = cfg.credentials()
    return HackerOneClient(
        username=creds.username,
        token=creds.token,
        base_url=cfg.get("h1", "base_url", default="https://api.hackerone.com/v1/"),
        user_agent=cfg.get("h1", "user_agent", default="vdp-pipeline/1.0"),
        rate_limit_rps=float(cfg.get("h1", "rate_limit_rps", default=2)),
        max_retries=int(cfg.get("h1", "max_retries", default=5)),
        backoff_base_seconds=float(cfg.get("h1", "backoff_base_seconds", default=1.0)),
        dry_run_submit=bool(cfg.get("h1", "dry_run_submit", default=True)),
    )
