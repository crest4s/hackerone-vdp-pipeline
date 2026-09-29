# AUTHORIZATION register

Record, per program, the explicit authorization under which you are testing.
**No program should be `enabled: true` in `config/programs.yaml` without a row
here.** This file is your audit trail.

| Handle | Program name | Authorized on (UTC) | Basis / link | Scope source | Notes |
|--------|--------------|---------------------|--------------|--------------|-------|
| example-program | Example Program (template) | 1970-01-01 | https://hackerone.com/example-program (ToS) | H1 structured scopes | TEMPLATE ROW — replace. `enabled:false`. |

## How to add a row
1. Join / accept the program on HackerOne.
2. Copy the program's policy / ToS URL (or the private-invite email reference).
3. Add a row above with the date you confirmed authorization.
4. Only then flip `enabled: true` in `config/programs.yaml`.

## Attestation
By enabling a program here you attest that:
- You have permission to test the listed in-scope assets.
- You will honour the program's scope, rate-limits and disclosure rules.
- You will not test out-of-scope assets, run destructive tests, or perform DoS.
