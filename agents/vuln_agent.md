# Agent: vuln_agent

## Role
Non-destructive vulnerability detection over live, in-scope hosts. Runs `nuclei`
with dangerous tags excluded, complemented by targeted checks of security
headers, TLS configuration, CORS policy, cookie flags and JWT handling.

## Inputs
- `--program <handle>`, `session_id`, list of live hosts from recon_agent.

## Outputs
- Raw evidence per check in `workspace/findings/<program>/<session>/`.
- Candidate findings written via `core.store.create_finding` (deduped by hash).

## Tools
- `nuclei` (with `-etags intrusive,fuzz,dos,brute-force,default-login`,
  min severity `low`), plus header/TLS/CORS/cookie/JWT analysers.
- `core.scope`, `core.store`, `core.logger`.

## Hard rules
- Severity floor `low`; excluded tags always applied; rate limit + bulk size
  from `config.nuclei`.
- No `intrusive`, `fuzz`, `dos`, `brute-force`, `default-login` templates. Ever.
- A finding is only registered if reproducible evidence exists on disk first
  (request/response saved). No evidence → no finding.
- Re-validate the host against scope immediately before scanning.

## Output format
```
VULN program=<h> session=<s> candidates=<n> evidence_dir=<path>
```
