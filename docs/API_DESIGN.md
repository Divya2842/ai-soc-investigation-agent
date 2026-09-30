# API Design

Base path: `/api`

## Implemented in Milestone 1

| Method | Path | Description |
|---|---|---|
| POST | `/api/alerts` | Ingest a new alert. Triggers deterministic IOC extraction and stores extracted IOCs. |
| GET | `/api/alerts` | List alerts (filter by `status`, `severity`, paginate with `limit`/`offset`). |
| GET | `/api/alerts/{id}` | Get one alert with its extracted IOCs. |
| GET | `/api/iocs` | List extracted IOCs (filter by `ioc_type`, `alert_id`). |
| GET | `/api/logs` | List simulated log events (filter by `log_type`, `hostname`, `user`). |
| GET | `/health` | Liveness/readiness, reports whether `GROQ_API_KEY` is configured. |

## Planned (later milestones, kept stable now so the frontend can be built against it)

| Method | Path | Milestone |
|---|---|---|
| GET | `/api/iocs/{id}/enrichment` | 2 |
| POST | `/api/alerts/{id}/investigate` | 4 |
| POST | `/api/investigations` | 4 |
| GET | `/api/investigations/{id}` | 4/5 |
| GET | `/api/mitre/attack/{technique_id}` | 3 |
| GET | `/api/mitre/atlas/{technique_id}` | 3 |
| POST | `/api/response/{investigation_id}/approve` | 6 |
| POST | `/api/response/{investigation_id}/reject` | 6 |

## Example: POST /api/alerts

Request:
```json
{
  "alert_id": "ALRT-1007",
  "alert_name": "Suspicious PowerShell Execution",
  "severity": "high",
  "timestamp": "2026-09-10T14:22:00Z",
  "source": "EDR",
  "user": "j.martinez",
  "hostname": "WKS-0231",
  "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
  "description": "Encoded PowerShell command spawned from winword.exe",
  "raw_event": { "...": "..." }
}
```

Response `201`:
```json
{
  "id": "b7e5...",
  "alert_id": "ALRT-1007",
  "status": "new",
  "extracted_iocs": [
    { "ioc_type": "sha256", "value": "..." }
  ]
}
```
