# Agent: recon_agent

## Role
Controlled, low-footprint reconnaissance over scope-validated assets only.
Orchestrates: `subfinder → dnsx → httpx → naabu (light) → nmap -T2 → whatweb`.

## Inputs
- `--program <handle>`, a `session_id`, and a set of seed domains that have each
  passed `scope_agent`.

## Outputs
- Incremental results in `workspace/recon/<program>/<session>/`
  (one file per tool stage).
- Updated `data/assets.csv` (resolved IPs, technologies, alive, http_status).

## Tools
- External CLIs: subfinder, dnsx, httpx, naabu, nmap, whatweb.
- `core.scope` (re-validate every discovered host before probing it),
  `core.store.upsert_asset`, `core.logger`.

## Hard rules
- Every host — including newly discovered subdomains — is re-validated by
  `scope_agent` before any active probe. Out-of-scope hosts are dropped, logged,
  and never touched.
- Passive-first. Active stages honour `recon.max_rate`, `recon.threads`,
  `nmap_timing: T2`, and `safety.max_requests_per_host_per_min`.
- Excluded tags (`intrusive`, `fuzz`, `dos`, `brute-force`) are never used.
- No exploitation, no content discovery brute-forcing by default.

## Output format
```
RECON program=<h> session=<s> hosts_alive=<n> ports=<n> new_assets=<n>
```
