# Security Playbooks (Response Recommendation Reference)

These are the deterministic playbook entries the risk/response layer
consults when generating a recommended action. The LLM may explain
these but does not invent new ones.

| Trigger condition | Recommended action |
|---|---|
| Malware execution confirmed on endpoint | Recommend endpoint isolation |
| Credential dumping (LSASS access) confirmed | Recommend endpoint isolation + forced password reset for logged-on accounts |
| Confirmed C2 beaconing to malicious IP/domain | Recommend endpoint isolation + block IOC at perimeter |
| Phishing credential submission confirmed | Recommend password reset + mailbox rule/OAuth grant review |
| Brute force followed by successful logon | Recommend password reset + review account activity |
| Lateral movement (WMI/PsExec) from a workstation | Recommend isolate source workstation + review target host for persistence |
| Low-confidence / unknown-reputation IOCs only | Recommend continued monitoring, no immediate action |

All "isolation", "disable account", and "block" actions are
**recommendations only** in this system. They require explicit human
approval via `POST /api/response/{investigation_id}/approve` before
being simulated and logged; nothing is ever executed automatically.
