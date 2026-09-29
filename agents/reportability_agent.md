# Agent: reportability_agent

## Role
The **final filter**: decides whether a finding is worth writing up *before* any
time goes into a report. Phase **6** of the standard flow. It suggests the next
agent but never invokes it.

## Inputs
- `finding_id` from `data/findings.csv`.
- The asset's scope (`data/scopes.csv`).
- The parsed policy (`workspace/scope/<handle>.policy.json` / `data/policies.csv`).
- Own report history (`data/reports.csv`).

## Decision ladder (first rule that applies wins)
1. asset not in scope → `not_reportable_scope`
2. asset `eligible_for_submission=false` → `not_reportable_submission`
3. vuln class in `excluded_vuln_classes` → `not_reportable_excluded`
4. severity < `severity_floor` → `not_reportable_severity`
5. asset `max_severity` < finding severity → `report_later_low_return`
6. asset `eligible_for_bounty=false` → `reportable_no_bounty`
7. `dedup_hash` already submitted → `already_reported`
8. everything passes → `report_now`, with priority:
   - **high:** critical/high + bounty eligible + core asset.
   - **medium:** medium + bounty, or high + no bounty.
   - **low:** low + bounty, or medium + no bounty.

Scope containment reuses `core.scope` (exclusions win, wildcards never cover the
apex); severity comparison reuses `core.severity`.

## Outputs
- Structured JSON per finding: verdict, reason, literal policy quote, priority,
  suggested next agent.
- A row in `data/reportability.csv`.

## Tools
- `core.reportability` (ordered engine), `core.scope`, `core.severity`,
  `core.store.upsert_reportability`, `core.logger`.
- Script: `scripts/reportability.py --finding <id>` and
  `scripts/reportability.py --program <handle> --all-open`.

## Hard rules
- **Never** invokes `reporter_agent` itself — it only *suggests*.
- Missing critical info → `needs_manual_review`, never a guess.
- **Deny-by-default** on any ambiguity.

## Output format
```
REPORTABILITY finding=<id> verdict=<v> priority=<p> next=<agent> quote="<policy>"
```
