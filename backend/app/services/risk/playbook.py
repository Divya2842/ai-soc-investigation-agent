"""
Deterministic playbook lookup for response recommendations. Mirrors
data/knowledge_base/security_playbooks.md -- kept as code here so it's
enforceable, with the markdown doc serving as the human-readable/RAG copy.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlaybookEntry:
    condition: str
    action: str


def recommend_actions(
    *,
    malware_detected: bool,
    credential_dumping: bool,
    c2_beaconing: bool,
    phishing_confirmed: bool,
    brute_force_success: bool,
    lateral_movement: bool,
    max_ioc_confidence: float,
) -> list[str]:
    actions: list[str] = []

    if credential_dumping:
        actions.append("Recommend endpoint isolation")
        actions.append("Recommend forced password reset for accounts logged on to the host")
    if malware_detected and "Recommend endpoint isolation" not in actions:
        actions.append("Recommend endpoint isolation")
    if c2_beaconing:
        if "Recommend endpoint isolation" not in actions:
            actions.append("Recommend endpoint isolation")
        actions.append("Recommend blocking the malicious IOC at the network perimeter")
    if phishing_confirmed:
        actions.append("Recommend password reset for the affected account")
        actions.append("Recommend reviewing mailbox rules and OAuth grants for persistence")
    if brute_force_success:
        actions.append("Recommend password reset for the affected account")
        actions.append("Recommend reviewing recent account activity for anomalies")
    if lateral_movement:
        actions.append("Recommend isolating the source workstation")
        actions.append("Recommend reviewing the target host for persistence mechanisms")

    if not actions:
        if max_ioc_confidence < 0.3:
            actions.append("Recommend continued monitoring; no immediate action required")
        else:
            actions.append("Recommend analyst review before taking action")

    # De-duplicate while preserving order.
    seen = set()
    deduped = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            deduped.append(a)
    return deduped
