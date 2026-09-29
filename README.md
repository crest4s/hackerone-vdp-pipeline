# VDP Pipeline — Authorized Bug-Bounty Automation for HackerOne

A reproducible, auditable, safety-first pipeline for **authorized** vulnerability
disclosure work on HackerOne programs. It syncs programs/scopes from the official
HackerOne API, enforces scope as a hard gate, orchestrates non-destructive recon
and testing, and produces HackerOne-format reports — while keeping a persistent,
queryable history in plain CSV.

> ⚠️ **Authorized use only.** Run this exclusively against assets you are
> explicitly, in-writing authorized to test (in-scope on a program you have
> joined). Record that authorization in `docs/AUTHORIZATION.md`. Out-of-scope or
> unauthorized testing is prohibited by design and by law.

## Purpose
1. Sync programs and structured scopes from the HackerOne API.
2. Enforce scope on every target (deny-by-default) before any active action.
3. Orchestrate controlled, non-destructive recon and safe-template testing.
4. Draft findings in strict HackerOne format and triage them by severity.
5. Keep a persistent, diffable history (CSV) with a full JSONL audit trail.
6. Respect rate-limits, scope and each program's rules.

## Architecture
```
                        ┌──────────────────┐
   researcher intent →  │   orchestrator   │  (claude.md, agents/orchestrator.md)
                        └────────┬─────────┘
             ┌───────────────────┼─────────────────────────────┐
             ▼                   ▼                             ▼
      ┌────────────┐      ┌────────────┐                ┌────────────┐
      │  h1_agent  │      │ scope_agent│  ── HARD GATE  │memory_agent│ (read-only)
      └─────┬──────┘      └─────┬──────┘                └─────┬──────┘
            │ sync              │ allow/deny                  │ queries
            ▼                   ▼                             ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  core/  (shared libs)                                          │
   │   h1_api · scope · store · csvstore · config · logger         │
   └───────┬───────────────────────────────┬───────────────────────┘
           ▼                               ▼
      ┌────────────┐   validated hosts ┌────────────┐   findings  ┌────────────┐
      │ recon_agent│ ────────────────▶ │ vuln_agent │ ──────────▶ │triage_agent│
      └─────┬──────┘                   └─────┬──────┘             └─────┬──────┘
            │ assets.csv                     │ evidence                │ triaged
            ▼                               ▼                          ▼
   data/*.csv (history)          workspace/ (evidence)        ┌────────────────┐
   workspace/logs/*.jsonl (audit)                             │ reporter_agent │→ report.md + finding.json (dry-run)
                                                              └────────────────┘
```

- **`core/`** — shared Python: API client, scope engine, CSV store, config, logger.
- **`agents/`** — Markdown role definitions (one file per agent).
- **`scripts/`** — CLI entry points.
- **`config/`** — technical config + the program registry.
- **`data/`** — CSV history (git-ignored).
- **`workspace/`** — runtime evidence + logs (git-ignored).
- **`templates/`** — report template + finding schema.

## Requirements
- Python 3.11+ (tested on 3.14).
- The recon/vuln *agents* shell out to standard open-source tools you install
  separately (subfinder, dnsx, httpx, naabu, nmap, whatweb, nuclei). The Python
  core does not require them.

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure HackerOne credentials
Create an API token at <https://hackerone.com/settings/api_token/edit>, then:
```bash
cp .env.example .env
# edit .env and set H1_USERNAME and H1_API_TOKEN
```
Credentials are read from environment variables only; `.env` is git-ignored.

## Usage policy (read before running anything active)
- Only act on programs with `enabled: true` in `config/programs.yaml` **and** an
  entry in `docs/AUTHORIZATION.md`.
- Every target passes `scope_validate.py` first. Exit code `2` means out-of-scope
  and blocks the pipeline.
- Non-destructive by default: `intrusive`, `fuzz`, `dos`, `brute-force`,
  `default-login` are always excluded.
- Report submission is dry-run by default and requires explicit human confirmation.

## Example invocations
```bash
# 1. Sync a program's scopes (read-only)
python scripts/h1_sync.py --program acme

# 2. Validate a target (exit 0 = in scope, 2 = out of scope)
python scripts/scope_validate.py --program acme --target app.acme.com

# 3. Bootstrap a supervised session (sync → scope gate → session dirs)
scripts/run_pipeline.sh acme app.acme.com

# 4. See the current state
python scripts/dashboard.py

# 5. Snapshot the history (backup / diff)
python scripts/export_history.py --markdown
```
Then, in Claude Code, drive the manual stages:
> "Claude, modo recon_agent — recon pasivo sobre acme."

## Troubleshooting
| Symptom | Cause / fix |
|---------|-------------|
| `Missing HackerOne credentials` | `.env` not set / not exported. Copy `.env.example`. |
| `HTTP 401 Unauthorized` | Wrong username or token; regenerate the token. |
| `SCOPE DENY ... no scope data` | Run `h1_sync.py` first to populate scopes. |
| `rich not installed` | `pip install -r requirements.txt` (dashboard falls back to plain text). |
| Repeated `HTTP 429` | Lower `h1.rate_limit_rps` / `nuclei.rate_limit` in `config/config.yaml`. |

## Safety & ethics
This tooling is built to keep you inside authorization: scope is a hard gate,
dangerous tooling is excluded by default, everything is logged, and submission is
human-confirmed. Do not remove these guardrails. See `docs/RUNBOOK.md` and
`docs/AUTHORIZATION.md`.
