# Database Schema (SQLite via SQLAlchemy)

Milestone 1 implements `alerts`, `iocs`, and `raw_log_events`. Later tables
(`ioc_enrichments`, `mitre_matches`, `atlas_matches`, `investigations`,
`response_actions`, `audit_log`) are documented here now so the schema
doesn't need reshaping later, and are implemented in the milestones noted.

## alerts  (Milestone 1)
| column | type | notes |
|---|---|---|
| id | str (UUID) PK | |
| alert_id | str, unique | external/source alert identifier |
| alert_name | str | |
| severity | str | as reported by the source, pre-risk-engine |
| timestamp | datetime | |
| source | str | e.g. "EDR", "Sentinel-sim", "Firewall" |
| user | str, nullable | |
| hostname | str, nullable | |
| source_ip | str, nullable | |
| destination_ip | str, nullable | |
| command_line | str, nullable | |
| file_hash | str, nullable | |
| domain | str, nullable | |
| url | str, nullable | |
| description | text | |
| raw_event | JSON | full original event payload |
| status | str | "new" \| "investigating" \| "closed" |
| created_at | datetime | |

## iocs  (Milestone 1)
| column | type | notes |
|---|---|---|
| id | str (UUID) PK | |
| alert_id | FK -> alerts.id | |
| ioc_type | str | ipv4 \| ipv6 \| domain \| url \| md5 \| sha1 \| sha256 \| email |
| value | str | normalized value |
| first_extracted_at | datetime | |

Unique constraint on `(alert_id, ioc_type, value)` to keep extraction
idempotent/deduplicated per alert.

## raw_log_events  (Milestone 1 — simulated SOC data)
| column | type | notes |
|---|---|---|
| id | str (UUID) PK | |
| log_type | str | windows_security \| powershell \| auth \| network \| endpoint \| dns \| process \| firewall |
| timestamp | datetime | |
| hostname | str, nullable | |
| user | str, nullable | |
| source_ip | str, nullable | |
| destination_ip | str, nullable | |
| payload | JSON | full simulated log record |

## ioc_enrichments  (Milestone 2)
ioc_id FK, provider, source ("local_mock"|external name), reputation,
confidence, first_seen, last_seen, related_malware (JSON list),
related_threat_actor, asn, isp, country, raw_response (JSON).

## mitre_attack_matches / mitre_atlas_matches  (Milestone 3)
investigation_id FK, technique_id, technique_name, tactic, evidence_refs
(JSON list of ids into iocs/raw_log_events), rationale.

## investigations  (Milestone 4/5)
alert_id FK, verdict, severity (from risk engine — source of truth),
confidence, summary, findings (JSON), recommended_actions (JSON),
risk_score (numeric), risk_factors (JSON), created_at.

## response_actions  (Milestone 6)
investigation_id FK, action_type, status ("recommended"|"approved"|"rejected"|"simulated_executed"),
approved_by, approved_at, simulated_result.

## audit_log  (Milestone 2+, incremental)
timestamp, actor ("system"|"llm"|username), alert_id, investigation_id,
tool_called, tool_input (JSON), tool_result (JSON), decision, notes.
