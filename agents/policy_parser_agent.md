# Agent: policy_parser_agent

## Role
Turns a program's free-text policy into an **actionable, auditable** structure,
so every later decision (planning, reportability) can cite the exact rule it
relied on. Phase **0** of the standard flow.

## Inputs
- `policy_md` column of `data/programs.csv` (free-text policy).
- The textual "Out of Scope" of `workspace/scope/<handle>.json` (structured scope).

## Method (documented heuristics — NOT naïve regex)
Segment the text into recognised sections and read each field only from the
sections that govern it:
- In Scope · Out of Scope · Excluded · Prohibited · Rules of Engagement ·
  Reporting Requirements · Rewards · Response Targets.

## Fields extracted (each with a literal `source_quote`)
- `allowed_testing` — manual / automated / authenticated… + conditions.
- `prohibited_actions` — DoS, aggressive fuzzing, spam, social eng., physical…
- `excluded_vuln_classes` — self-XSS, missing headers, clickjacking, CSRF on
  login, open redirect without impact, etc.
- `severity_floor` — minimum accepted severity.
- `bounty_eligibility_rules` — bounty vs swag vs recognition.
- `report_requirements` — format, minimum PoC, video, language…
- `rate_limits_declarados` — declared max rate, if any.
- `window_de_testing` — testing windows/hours, if any.
- `red_flags` — "only manual", "no automated tools", "contact before testing"…

## Outputs
- `workspace/scope/<handle>.policy.json` (structured).
- `workspace/scope/<handle>.policy.md` (human-readable, every claim quoted).
- A row in `data/policies.csv`.

## Tools
- `core.policy` (segmenter + extractors), `core.store.upsert_policy`, `core.logger`.
- Script: `scripts/parse_policy.py --program <handle>`.

## Hard rules
- **Never invent** a rule that is not in the text.
- Any unclear section → `needs_manual_review: true` + list what is missing.
- **Deny-by-default:** liberal detecting prohibitions/exclusions (safe direction),
  strict detecting `allowed_testing` (explicit statement required, else empty).

## Output format
```
POLICY program=<h> sections=<n> excluded=<n> floor=<sev> manual_review=<bool> json=<path>
```
