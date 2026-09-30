# Detection Engineering Guidance

## PowerShell abuse
Encoded (`-enc`/`-EncodedCommand`) or hidden-window PowerShell spawned
from an Office application (WINWORD.EXE, EXCEL.EXE) is a strong signal
of a malicious macro or embedded object, not routine admin activity.

## Credential dumping
Any process other than a known, allow-listed backup/EDR agent
requesting `PROCESS_VM_READ` access to `lsass.exe`, or using
`comsvcs.dll`'s `MiniDump` export against the LSASS PID, should be
treated as credential dumping until proven otherwise.

## Lateral movement
WMI (`wmic /node:...`) or PsExec-style remote process creation
originating from a workstation (not a management/jump host) toward a
server, especially shortly after suspicious activity on that
workstation, is a strong lateral-movement indicator.

## Newly-registered domains
Domains younger than ~30 days that are contacted by an endpoint,
especially ones that typosquat a well-known brand (e.g.
`secure-office365-login.top`), warrant a high suspicion prior even
before enrichment confirms malicious reputation.
