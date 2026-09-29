# `data/` — CSV history schema

Every CSV here is managed exclusively by `core/csvstore.py`. Columns are defined
centrally in `SCHEMA`. All timestamps are **ISO-8601 UTC** (e.g.
`2026-09-29T14:03:00+00:00`). Booleans are stored as `true` / `false` strings.

The CSV files themselves are **git-ignored** (they may contain program-specific
data); only this README and `.gitkeep` are tracked.

## `programs.csv`
| column | type | meaning |
|--------|------|---------|
| handle | str | HackerOne program handle (primary key). |
| name | str | Human-readable program name. |
| state | str | Program state (e.g. `public_mode`, `soft_launched`). |
| bounty | bool-ish | Whether the program offers bounties. |
| last_synced_at | datetime | Last successful sync. |

## `scopes.csv`  (key: program + asset)
| column | type | meaning |
|--------|------|---------|
| program | str | Program handle. |
| asset | str | Asset identifier (domain, `*.wildcard`, IP/CIDR, etc.). |
| asset_type | str | H1 asset type (URL, CIDR, etc.). |
| in_scope | bool | Whether the asset is eligible/in-scope. |
| severity_max | str | Max severity accepted for this asset. |
| eligible_for_bounty | bool | Bounty eligible. |
| eligible_for_submission | bool | Submission eligible. |
| notes | str | Program instructions for the asset. |

## `assets.csv`  (key: program + asset)
| column | type | meaning |
|--------|------|---------|
| program | str | Program handle. |
| asset | str | Discovered host/URL. |
| resolved_ips | str | Comma-separated resolved IPs. |
| technologies | str | Detected technologies. |
| alive | bool | Responded to probing. |
| http_status | str | Last observed HTTP status. |
| first_seen | datetime | First discovery. |
| last_seen | datetime | Most recent observation. |

## `findings.csv`  (key: id)
| column | type | meaning |
|--------|------|---------|
| id | int | Auto-increment id. |
| program | str | Program handle. |
| title | str | Finding title. |
| severity | str | `low`/`medium`/`high`/`critical`. |
| cvss_vector | str | CVSS 3.1 vector string. |
| cvss_score | float | CVSS 3.1 base score. |
| cwe | str | CWE id (e.g. `CWE-79`). |
| asset | str | Affected asset. |
| status | str | `new`/`triaged`/`duplicate`/`rejected`/`reported`/`resolved`. |
| dedup_hash | str | `sha256(program|asset|vuln_class|normalized_endpoint)`. |
| report_path | str | Path to the rendered report, if any. |
| created_at | datetime | Creation time. |
| updated_at | datetime | Last update. |

## `reports.csv`  (key: id)
| column | type | meaning |
|--------|------|---------|
| id | int | Auto-increment id. |
| finding_id | int | FK to `findings.id`. |
| version | int | Report revision. |
| path | str | Path to the report file. |
| submitted_at | datetime | When submitted to H1 (empty if dry-run). |
| h1_report_id | str | HackerOne report id, once submitted. |
| state | str | `draft`/`submitted`/`triaged`/`resolved`/`duplicate`. |
| triaged_at | datetime | When H1 triaged it. |
| bounty_amount | float | Bounty paid, if any. |

## `sessions.csv`  (key: id)
| column | type | meaning |
|--------|------|---------|
| id | int | Auto-increment id. |
| program | str | Program handle. |
| agent | str | Agent that opened the session. |
| started_at | datetime | Session start. |
| ended_at | datetime | Session end (empty if open). |
| tools_used | str | Comma-separated tools. |
| stats_json | json | Free-form stats blob. |

## `events.csv`  (append-only)
| column | type | meaning |
|--------|------|---------|
| ts | datetime | Event time. |
| session_id | str | Owning session id. |
| agent | str | Emitting agent. |
| level | str | `debug`/`info`/`warning`/`error`/`critical`. |
| message | str | Human-readable message. |
| payload_json | json | Structured payload. |
