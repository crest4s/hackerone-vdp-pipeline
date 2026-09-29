# RUNBOOK — Operating the VDP pipeline

Operational procedures. Keep this current; it is the on-call reference.

## Add a new program
1. Confirm you have **written authorization** (private invite accepted, or the
   program is public and you have joined it).
2. Record it in `docs/AUTHORIZATION.md` (handle, date, link/email, notes).
3. Add a block in `config/programs.yaml`:
   ```yaml
   - handle: "newprog"
     name: "New Program"
     enabled: true            # only after authorization is recorded
     authorization_ref: "docs/AUTHORIZATION.md#newprog"
   ```
4. Sync: `python scripts/h1_sync.py --program newprog`.
5. Verify scopes: `python scripts/scope_validate.py --program newprog --target <in-scope-host>`.

## Pause the pipeline
- Fast: set `enabled: false` for the program(s) in `config/programs.yaml`.
- Global stop of active work: set `safety.require_scope_validation: true` (default)
  and simply do not launch recon/vuln agents. To hard-stop API calls, unset the
  credentials (see "Revoke token").

## Revoke / rotate the HackerOne token
1. Revoke at <https://hackerone.com/settings/api_token/edit>.
2. Remove it locally: `unset H1_API_TOKEN` and delete the line from `.env`.
3. Generate a new token, update `.env`, re-source it.
4. The token never appears in git (see `.gitignore`) or in logs.

## Purge local data
```bash
# Remove CSV history (irreversible — export first if needed):
rm -f data/*.csv
# Remove runtime evidence and logs:
rm -rf workspace/recon/* workspace/findings/* workspace/reports/* \
       workspace/scope/* workspace/logs/*
```
The `.gitkeep` files keep the directory structure intact.

## Back up the history
```bash
python scripts/export_history.py --markdown
# Snapshot lands in workspace/reports/history/<timestamp>/
# Copy that directory to your encrypted backup location.
```

## Migrate CSV history to another machine
1. `python scripts/export_history.py` on the source machine.
2. Securely copy `data/*.csv` (or the snapshot dir) to the new machine's `data/`.
3. Re-create `.env` from `.env.example` on the new machine (do NOT copy secrets in
   the clear; regenerate the token if the transfer channel was untrusted).
4. Verify: `python scripts/dashboard.py`.

## Incident: accidental out-of-scope contact
1. Stop all active agents immediately.
2. Capture the relevant `workspace/logs/<date>.jsonl` lines as evidence.
3. If a program requires disclosure of such events, follow their policy.
4. Tighten scope data (`h1_sync.py`) and re-test the scope gate before resuming.
