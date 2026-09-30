# SOC Investigation Procedures

## Triage
1. Confirm the alert fired on real activity, not a known benign pattern.
2. Identify the affected host, user, and time window.
3. Extract all IOCs from the alert (IPs, domains, URLs, hashes, emails).

## Evidence gathering
- Pull logs for the affected host and user across a window of at least
  +/- 30 minutes around the alert timestamp.
- Correlate process creation, network connections, and authentication
  events on the same host/user.
- Enrich every extracted IOC before drawing conclusions about reputation.

## Escalation criteria
- Escalate to Critical if credential dumping, ransomware behavior, or
  confirmed C2 communication is observed.
- Escalate to High if a malicious IOC is confirmed AND there is evidence
  of execution or lateral movement.
- Medium/Low findings should still be logged and enrichment cached for
  future correlation, even if no immediate action is taken.

## Documentation
Every investigation should record: what evidence was reviewed, what
was NOT found (absence of lateral movement, absence of data
exfiltration, etc. is meaningful), and the specific recommended
response action with justification.
