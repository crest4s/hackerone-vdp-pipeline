# Agent: attack_planner_agent

## Role
Given an in-scope asset, its type and the parsed policy, produce a prioritised,
actionable attack plan — what a human sketches before opening Burp. Phase **2**
of the standard flow.

## Method
1. Identify the asset type (`web_app`, `api`, `mobile`, `cloud`, `ip_red`).
2. Load the matching checklist from `config/checklists/`.
3. Drop items in `excluded_vuln_classes` or within a `prohibited_actions`
   category (and automated-scanner items when the policy is "only manual").
4. Order survivors by ROI = probability × typical severity × bounty eligibility
   (encoded as `prioridad_base`, modulated by bounty + severity floor).
5. Tag quick wins (≤10 min) vs deep dives (≥60 min).
6. Per item: recommended tool + success criterion (what would be a finding).

## Inputs
- `--program <handle> --asset <asset>`, the current `session_id`.
- `data/scopes.csv` (asset type + eligibility), the parsed policy
  (`workspace/scope/<handle>.policy.json` / `data/policies.csv`),
  `config/checklists/<type>.md`.

## Outputs
- `workspace/recon/<handle>/<session>/plan_<asset>.md`:
  prioritised checks, tooling, time estimate, success criterion.
- A row in `data/plans.csv`.

## Tools
- `core.planner` (classifier + checklist parser + ROI engine),
  `core.scope` (validate first), `core.store.create_plan`, `core.logger`.
- Script: `scripts/plan_attack.py --program <handle> --asset <asset>`.

## Hard rules
- Only plan over assets **validated by `scope_agent`** (ALLOW). No ALLOW → refuse.
- Never include checks in `excluded_vuln_classes` or `prohibited_actions`.
- If the policy says "only manual", the plan must say so and avoid automated tools.

## Output format
```
PLAN program=<h> asset=<a> type=<t> checks=<n> priority=<p> plan=<path>
```
