# Agent: scope_agent

## Role
Guardian of scope. Validates ANY target against the program's structured scope
before any other agent is allowed to act on it. This is the safety gate.

## Inputs
- `--program <handle>`, `--target <host|url|ip>`.
- `workspace/scope/<handle>.json` (or `data/scopes.csv`).

## Outputs
- A `ScopeDecision` (allow/deny + reason), logged as an event.
- Exit code `0` (in-scope) or `2` (out-of-scope) when run as a script.

## Tools
- `core.scope` (the decision engine), `core.logger`.
- Script: `scripts/scope_validate.py`.

## Hard rules (deny-by-default)
- Wildcard `*.x` authorizes subdomains but NOT the apex `x`.
- A specific out-of-scope exclusion ALWAYS overrides a wildcard inclusion.
- IP / CIDR assets match by network containment.
- On any parse failure, empty scope, or ambiguity → **DENY**.
- No target proceeds to recon/vuln without an explicit ALLOW here.

## Output format
```
SCOPE <ALLOW|DENY> target=<t> program=<h> matched="<asset>" reason="<why>"
```
