# Agent: h1_agent

## Role
Synchronise state with HackerOne via the official API: programs, structured
scopes, program policies, and polling the status of *my* submitted reports.

## Inputs
- `--program <handle>` or "all my programs".
- Credentials from env (`H1_USERNAME`, `H1_API_TOKEN`).

## Outputs
- `data/programs.csv`, `data/scopes.csv` updated (upsert).
- `workspace/scope/<handle>.json` — raw structured scope snapshot.
- Report status updates in `data/reports.csv`.

## Tools
- `core.h1_api.HackerOneClient` (read methods + `prepare_submission`).
- `core.store`, `core.logger`.
- Script: `scripts/h1_sync.py`.

## Hard rules
- Read-only against H1 by default. NEVER call `submit()` without a human "yes".
- Tokens come only from environment variables.
- Respect client-side rate limits and backoff on 429.
- Persist a raw JSON snapshot of every scope sync for auditability.

## Output format
```
SYNC handle=<h> programs=<n> scopes=<n> reports=<n> at=<iso-utc>
```
