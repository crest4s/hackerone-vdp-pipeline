#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#  run_pipeline.sh — Bootstrap one program's session, safely.
#
#  This script performs ONLY the safe, automatable groundwork:
#     1. Sync programs + scopes from HackerOne (read-only).
#     2. Validate the seed target against scope (hard gate).
#     3. Generate a session_id and prepare the workspace directories.
#
#  It then prints the exact Claude Code prompts to run the *manual*,
#  human-supervised stages (recon, vuln, triage, report). Those stages are
#  intentionally NOT auto-run: they touch live assets and require judgement.
#
#  Usage:
#     scripts/run_pipeline.sh <program_handle> <seed_target>
#  Example:
#     scripts/run_pipeline.sh acme app.acme.com
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

PROGRAM="${1:-}"
TARGET="${2:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="python3"

if [[ -z "$PROGRAM" || -z "$TARGET" ]]; then
  echo "usage: $0 <program_handle> <seed_target>" >&2
  exit 64
fi

echo "═══════════════════════════════════════════════════════════════"
echo " Pipeline bootstrap: program=$PROGRAM target=$TARGET"
echo "═══════════════════════════════════════════════════════════════"

# ── 0. Authorization gate (advisory): warn if no auth record ───────────
if ! grep -qi "$PROGRAM" "$ROOT/docs/AUTHORIZATION.md" 2>/dev/null; then
  echo "!! WARNING: no authorization record for '$PROGRAM' in docs/AUTHORIZATION.md."
  echo "!! Record your written authorization before running any active tooling."
fi

# ── 1. Sync (read-only) ────────────────────────────────────────────────
echo "[1/3] Syncing program + scopes from HackerOne ..."
if ! "$PY" "$ROOT/scripts/h1_sync.py" --program "$PROGRAM"; then
  echo "!! Sync failed (check credentials / network). Continuing to scope check."
fi

# ── 2. Scope validation (HARD GATE) ────────────────────────────────────
echo "[2/3] Validating target against scope ..."
set +e
"$PY" "$ROOT/scripts/scope_validate.py" --program "$PROGRAM" --target "$TARGET"
RC=$?
set -e
if [[ "$RC" -ne 0 ]]; then
  echo "✗ Target '$TARGET' is NOT in scope (rc=$RC). Aborting — nothing active will run."
  exit "$RC"
fi
echo "✓ Target is in scope."

# ── 3. Session bootstrap ───────────────────────────────────────────────
SESSION_ID="$(date -u +%Y%m%dT%H%M%SZ)-$PROGRAM"
mkdir -p "$ROOT/workspace/recon/$PROGRAM/$SESSION_ID" \
         "$ROOT/workspace/findings/$PROGRAM/$SESSION_ID" \
         "$ROOT/workspace/reports/$PROGRAM"
echo "[3/3] Session ready: $SESSION_ID"

cat <<INSTRUCTIONS

───────────────────────────────────────────────────────────────
 Groundwork done. The next stages are MANUAL and human-supervised.
 In Claude Code, ask for them one at a time, e.g.:

   1) Recon:
      "Claude, modo recon_agent — recon pasivo sobre $PROGRAM,
       sesión $SESSION_ID, seed $TARGET."

   2) Vuln (safe, non-destructive):
      "Claude, modo vuln_agent — nuclei safe sobre hosts vivos de
       $PROGRAM, sesión $SESSION_ID."

   3) Triage:
      "Claude, modo triage_agent — evalúa los findings nuevos de
       $PROGRAM."

   4) Report (dry-run):
      "Claude, modo reporter_agent — redacta el finding #<id>."

 Every discovered host is re-checked by scope_agent before it is
 touched. Nothing is submitted to HackerOne without your explicit
 confirmation.
───────────────────────────────────────────────────────────────
INSTRUCTIONS
