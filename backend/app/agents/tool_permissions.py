"""
Explicit tool allow-list per agent graph node. This is enforced by the
graph itself (each node only ever calls the functions listed here for it)
-- it is not a suggestion given to the LLM that it could ignore. If a node
needs a new capability, it must be added here deliberately.
"""
from __future__ import annotations

TOOL_PERMISSIONS: dict[str, list[str]] = {
    "alert_triage": [],
    "extract_iocs": ["extract_iocs"],
    "enrich_iocs": ["enrich_ip", "enrich_domain", "enrich_url", "enrich_hash"],
    "investigate_logs": ["search_logs", "get_user_activity", "get_host_activity"],
    "map_attack": ["map_mitre_attack"],
    "map_atlas": ["map_mitre_atlas"],
    "correlate_evidence": [],
    "assess_risk": ["calculate_risk"],
    "summarize_investigation": [],  # LLM call only, no tool access -- evidence is already assembled
    "recommend_response": ["recommend_actions"],
}

ALL_TOOLS = sorted({tool for tools in TOOL_PERMISSIONS.values() for tool in tools})


def tools_allowed_for(node: str) -> list[str]:
    return TOOL_PERMISSIONS.get(node, [])
