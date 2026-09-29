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

- **`core/`** — shared Python: API client, scope engine, CSV store, config, logger,
  plus the analyst engines (`scoring`, `policy`, `planner`, `reportability`, `severity`).
- **`agents/`** — Markdown role definitions (one file per agent, 13 total).
- **`scripts/`** — CLI entry points.
- **`config/`** — technical config, the program registry, `scoring.yaml`, and
  `checklists/` (WSTG / API Top 10 / MASVS / cloud / network).
- **`data/`** — CSV history (git-ignored).
- **`workspace/`** — runtime evidence, logs and plans (git-ignored).
- **`templates/`** — report template + finding schema.

## The full analyst flow (12 phases)
The pipeline no longer only *executes and reports* — it now models the **decisions**
a senior analyst makes: which program to attack, how to read the policy, how to
plan, and what is actually worth reporting.

```
  selección → política → sync → plan → recon → vuln → triage → reportability → reporte → cierre

 ┌──────────────────────┐
 │ -1 program_selector  │  rank programs by attractiveness today  → workspace/plans/…
 ├──────────────────────┤
 │  0 policy_parser      │  policy text → actionable structure     → …policy.json + policies.csv
 ├──────────────────────┤
 │  1 h1_agent           │  sync programs + structured scopes      → programs.csv / scopes.csv
 ├──────────────────────┤
 │  2 attack_planner     │  in-scope asset → prioritised plan       → plan_<asset>.md + plans.csv
 ├──────────────────────┤   (scope_agent is the HARD GATE before phases 2–4)
 │  3 recon_agent        │  discovery guided by the plan            → assets.csv
 ├──────────────────────┤
 │  4 vuln_agent         │  safe, non-destructive testing           → evidence + findings.csv
 ├──────────────────────┤
 │  5 triage_agent       │  technical validation (CVSS + CWE)       → findings.status=triaged
 ├──────────────────────┤
 │  6 reportability      │  final filter: is it worth a report?     → reportability.csv
 ├──────────────────────┤
 │  7 reporter_agent     │  HackerOne-format report (dry-run)       → report.md + finding.json
 ├──────────────────────┤
 │  8 orchestrator       │  close the session                       → sessions.ended_at
 └──────────────────────┘
```

### The four decision agents (new)
- **`program_selector_agent`** — ranks programs by 7 weighted, configurable
  criteria (bounty, triage speed, scope size/variety, competition, skill fit,
  freshness, personal saturation) and says *"start today with X"* and why.
  Never ranks a `enabled: false` program.
- **`policy_parser_agent`** — segments the policy into recognised sections and
  extracts allowed testing, prohibited actions, excluded vuln classes, severity
  floor, bounty rules, report requirements, rate limits, testing window and red
  flags — each with a literal `source_quote`. Deny-by-default on ambiguity.
- **`attack_planner_agent`** — turns an in-scope asset + parsed policy into an
  ROI-ordered checklist (quick wins vs deep dives), dropping anything the policy
  excludes or prohibits, and honouring "only manual" programs.
- **`reportability_agent`** — the final filter before you spend time writing:
  an ordered decision ladder that returns a verdict, a priority and the exact
  policy quote it relied on. It only *suggests* the next agent, never invokes it.

## Cómo se usa (secuencia real de comandos)
```bash
# -1) ¿A qué programa apunto hoy?
python scripts/rank_programs.py --top 3           # → workspace/plans/programs_ranking_<fecha>.md

#  1) Sincroniza programa + scopes (read-only)
python scripts/h1_sync.py --program acme

#  0) Parsea la política a algo accionable
python scripts/parse_policy.py --program acme      # → workspace/scope/acme.policy.json + policies.csv

#  gate) Valida el asset (exit 0 = in scope, 2 = out)
python scripts/scope_validate.py --program acme --target app.acme.com

#  2) Planifica el ataque sobre un asset in-scope
python scripts/plan_attack.py --program acme --asset app.acme.com

#  3–5) recon / vuln / triage → agentes manuales supervisados en Claude Code

#  6) ¿Merece reporte?  (uno, o todos los abiertos de un programa)
python scripts/reportability.py --finding 42
python scripts/reportability.py --program acme --all-open

# Ver todo el flujo con datos ficticios, sin tocar la red:
python scripts/simulate_session.py                 # → workspace/plans/_simulation/
```

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
