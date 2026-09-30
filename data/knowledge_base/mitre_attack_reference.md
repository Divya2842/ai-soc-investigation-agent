# MITRE ATT&CK Reference Notes

MITRE ATT&CK is a knowledge base of adversary tactics and techniques
based on real-world observations, organized into tactics (the "why",
e.g. Execution, Persistence, Credential Access) and techniques/
sub-techniques (the "how", e.g. T1059.001 PowerShell).

## Techniques relevant to this environment
- **T1059.001 (PowerShell)** — execution via the PowerShell engine,
  frequently obfuscated with Base64 encoding and hidden windows.
- **T1003.001 (LSASS Memory)** — credential dumping via direct memory
  access to the LSASS process.
- **T1047 (Windows Management Instrumentation)** and **T1021.002
  (SMB/Windows Admin Shares)** — common lateral movement techniques in
  Windows environments.
- **T1566.002 (Spearphishing Link)** — initial access via a malicious
  link in an email.
- **T1110 (Brute Force)** — repeated authentication attempts to guess
  credentials.

Mapping evidence to ATT&CK should always cite the specific evidence
(a log line, a command, a network connection) that supports the
technique -- never assign a technique ID based on the alert's title
alone.
