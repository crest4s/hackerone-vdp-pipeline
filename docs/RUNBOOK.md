# RUNBOOK — Operating the VDP pipeline

Operational procedures. Keep this current; it is the on-call reference.

## A full analyst session, from open to close
This is the exact sequence from opening Claude Code to closing the session. Each
phase is one agent; **★ marks a human decision point** where you review the
output and decide whether to continue. Nothing active runs without your ALLOW.

1. **Open Claude Code** in this repo and say: *"empieza una sesión de trabajo"*.
   The orchestrator activates the full flow from Fase -1 and stops after each phase.
2. **Fase -1 · program_selector** — `python scripts/rank_programs.py --top 3`.
   Read `workspace/plans/programs_ranking_<fecha>.md`.
   ★ **Decision:** accept the recommended program or pick another from the table.
3. **Fase 1 · h1_agent** — `python scripts/h1_sync.py --program <handle>` (read-only).
   Confirms `enabled: true` + an `AUTHORIZATION.md` record. ★ If either is missing,
   the run stops — record authorization first (see "Add a new program").
4. **Fase 0 · policy_parser** — `python scripts/parse_policy.py --program <handle>`.
   Read `workspace/scope/<handle>.policy.md`.
   ★ **Decision:** if `needs_manual_review: true`, read the policy yourself and
   fill the gaps before planning.
5. **gate · scope_agent** — `python scripts/scope_validate.py --program <handle> --target <asset>`.
   ★ Must return `ALLOW` (exit 0). A `DENY` (exit 2) blocks everything downstream.
6. **Fase 2 · attack_planner** — `python scripts/plan_attack.py --program <handle> --asset <asset>`.
   Read `workspace/recon/<handle>/<session>/plan_<asset>.md`.
   ★ **Decision:** approve the plan (or trim it) before touching the target.
7. **Fases 3–5 · recon → vuln → triage** — run the manual, human-supervised
   agents in Claude Code (see `scripts/run_pipeline.sh` for the exact prompts).
   Every discovered host is re-validated by `scope_agent` before it is probed.
8. **Fase 6 · reportability** — `python scripts/reportability.py --program <handle> --all-open`.
   Read `data/reportability.csv`.
   ★ **Decision:** only findings with `report_now` / `reportable_no_bounty`
   proceed. Everything else is filtered out (with the reason on record).
9. **Fase 7 · reporter_agent** — draft the report (dry-run).
   ★ **Decision:** review the draft. Submission to HackerOne is **never**
   automatic — it needs your explicit "yes" (see the dry-run guards).
10. **Fase 8 · orchestrator** — close the session (`end_session`). Snapshot the
    history if needed (`python scripts/export_history.py --markdown`).

To rehearse the whole decision chain without touching the network:
```bash
python scripts/simulate_session.py   # isolated demo in workspace/plans/_simulation/
```

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
