# Incident Response Procedures

## Containment (never automatic in this system)
- Endpoint isolation should be recommended when malware execution or C2
  beaconing is confirmed on a host, but must always require human
  approval before being simulated/executed.
- Disabling a user account should be recommended when credential misuse
  or account takeover is confirmed, again pending human approval.

## Credential dumping response
When LSASS memory access consistent with credential dumping is
confirmed:
1. Recommend isolating the affected host.
2. Recommend forcing a password reset for any accounts that were logged
   on to the host at the time of the dump.
3. Recommend hunting for use of the dumped credentials elsewhere in the
   environment (lateral movement check).

## Phishing response
When a user has submitted credentials to a phishing page:
1. Recommend an immediate password reset for the affected account.
2. Recommend checking for suspicious mailbox rules or OAuth grants
   (common post-compromise persistence for email-based attacks).
3. Recommend blocking the phishing domain at the email gateway/proxy.

## Brute force response
When a brute-force pattern is followed by a successful logon:
1. Treat the successful logon as compromised until proven otherwise.
2. Recommend a password reset and review of the account's recent
   activity for anomalies.
3. Recommend blocking/rate-limiting the source IP if it is external.
