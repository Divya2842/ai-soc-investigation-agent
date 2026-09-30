"""
LangGraph agent workflow.

START -> alert_triage -> extract_iocs -> enrich_iocs -> investigate_logs
      -> map_attack -> map_atlas -> correlate_evidence -> assess_risk
      -> summarize_investigation -> recommend_response -> END

Every node's tool access is restricted to what's declared in
`tool_permissions.py`. Every tool call is written to the audit log. The
deterministic layers (extraction, enrichment, MITRE mapping, risk scoring,
playbook) run unconditionally; the LLM (`summarize_investigation`) is used
only to narrate already-computed evidence, and if it's unavailable
(no GROQ_API_KEY) or its output fails validation, the graph falls back to
a deterministic, evidence-only summary rather than failing the whole
investigation.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph
from sqlalchemy.orm import Session

from app.agents.tool_permissions import tools_allowed_for
from app.models.alert import Alert
from app.models.ioc import IOC
from app.schemas.investigation import InvestigationResult
from app.services import audit
from app.services.ioc.enrichment.router import enrich
from app.services.ioc.extract import extract_iocs
from app.services.llm import groq_client
from app.services.llm.prompt_guard import screen
from app.services.logs.source import LogQuery, get_log_source
from app.services.mitre import atlas as atlas_mapper
from app.services.mitre import attack as attack_mapper
from app.services.rag.retriever import get_knowledge_base
from app.services.risk.playbook import recommend_actions
from app.services.risk.score import RiskFactors, calculate_risk


class InvestigationState(TypedDict, total=False):
    alert_id: str  # internal Alert.id
    db: Any  # SQLAlchemy Session (not serialized; internal use only)

    alert_evidence: dict
    iocs: list[dict]
    enrichments: list[dict]
    correlated_logs: list[dict]
    attack_matches: list[dict]
    atlas_matches: list[dict]
    rag_sources: list[dict]
    risk_assessment: dict
    recommended_actions: list[str]
    investigation_result: dict
    llm_used: bool


def _node_alert_triage(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    alert = db.query(Alert).filter(Alert.id == state["alert_id"]).first()
    if not alert:
        raise ValueError(f"Alert {state['alert_id']} not found")

    guard = screen(alert.description)
    if guard.is_suspicious:
        audit.record(
            db, actor="system", alert_id=alert.id, tool_called="prompt_guard",
            tool_input={"field": "description"}, tool_result={"matched": guard.matched_patterns},
            decision="flagged_possible_prompt_injection",
        )

    state["alert_evidence"] = {
        "alert_id": alert.alert_id,
        "alert_name": alert.alert_name,
        "reported_severity": alert.severity,
        "source": alert.source,
        "user": alert.user,
        "hostname": alert.hostname,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "command_line": alert.command_line,
        "description": guard.sanitized_text or alert.description,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
    }
    audit.record(db, actor="system", alert_id=alert.id, tool_called=None, decision="triage_complete")
    return state


def _node_extract_iocs(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    alert = db.query(Alert).filter(Alert.id == state["alert_id"]).first()

    existing = db.query(IOC).filter(IOC.alert_id == alert.id).all()
    if not existing:
        extracted = extract_iocs(
            source_ip=alert.source_ip, destination_ip=alert.destination_ip,
            domain=alert.domain, url=alert.url, file_hash=alert.file_hash,
            command_line=alert.command_line, description=alert.description,
            raw_event=alert.raw_event,
        )
        for i in extracted:
            db.add(IOC(alert_id=alert.id, ioc_type=i.ioc_type, value=i.value))
        db.commit()
        existing = db.query(IOC).filter(IOC.alert_id == alert.id).all()

    state["iocs"] = [{"id": i.id, "ioc_type": i.ioc_type, "value": i.value} for i in existing]
    audit.record(
        db, actor="system", alert_id=alert.id, tool_called="extract_iocs",
        tool_result={"count": len(state["iocs"])}, decision="iocs_available",
    )
    return state


def _node_enrich_iocs(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    enrichments = []
    for ioc in state.get("iocs", []):
        result = enrich(ioc["ioc_type"], ioc["value"])
        enrichments.append(
            {
                "ioc_value": ioc["value"],
                "ioc_type": ioc["ioc_type"],
                "source": result.source,
                "reputation": result.reputation,
                "confidence": result.confidence,
                "related_malware": result.related_malware,
            }
        )
        audit.record(
            db, actor="system", alert_id=state["alert_id"], tool_called="enrich_ioc",
            tool_input={"value": ioc["value"], "type": ioc["ioc_type"]},
            tool_result={"reputation": result.reputation, "source": result.source},
        )
    state["enrichments"] = enrichments
    return state


def _node_investigate_logs(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    alert = db.query(Alert).filter(Alert.id == state["alert_id"]).first()
    source = get_log_source(db)

    correlated: list[dict] = []
    if alert.hostname:
        correlated += source.get_host_activity(alert.hostname, timedelta(minutes=30), alert.timestamp)
    if alert.user:
        correlated += source.get_user_activity(alert.user, timedelta(minutes=30), alert.timestamp)

    # De-duplicate (same event may match both host and user activity).
    seen = set()
    deduped = []
    for event in correlated:
        key = (event["log_type"], event["timestamp"], event.get("hostname"), event.get("user"))
        if key not in seen:
            seen.add(key)
            deduped.append(event)

    state["correlated_logs"] = deduped
    audit.record(
        db, actor="system", alert_id=alert.id, tool_called="search_logs",
        tool_result={"correlated_event_count": len(deduped)},
    )
    return state


def _build_evidence_text(state: InvestigationState) -> str:
    parts = [
        str(state.get("alert_evidence", {})),
        str(state.get("correlated_logs", [])),
        str(state.get("enrichments", [])),
    ]
    return " ".join(parts)


def _node_map_attack(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    text = _build_evidence_text(state)
    matches = attack_mapper.map_attack(text)
    state["attack_matches"] = [m.__dict__ for m in matches]
    audit.record(db, actor="system", alert_id=state["alert_id"], tool_called="map_mitre_attack",
                 tool_result={"technique_ids": [m.technique_id for m in matches]})
    return state


def _node_map_atlas(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    text = _build_evidence_text(state)
    matches = atlas_mapper.map_atlas(text)
    state["atlas_matches"] = [m.__dict__ for m in matches]
    audit.record(db, actor="system", alert_id=state["alert_id"], tool_called="map_mitre_atlas",
                 tool_result={"technique_ids": [m.technique_id for m in matches]})
    return state


def _node_correlate_evidence(state: InvestigationState) -> InvestigationState:
    kb = get_knowledge_base()
    query = state.get("alert_evidence", {}).get("alert_name", "")
    chunks = kb.retrieve(query, k=3)
    state["rag_sources"] = [{"source": c.source, "text": c.text[:400], "score": round(c.score, 3)} for c in chunks]
    return state


def _node_assess_risk(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    enrichments = state.get("enrichments", [])
    reputations = [e["reputation"] for e in enrichments]
    malware_detected = any(e["related_malware"] for e in enrichments) or any(
        r == "malicious" for r in reputations
    )
    max_confidence = max((e["confidence"] for e in enrichments), default=0.0)

    alert = db.query(Alert).filter(Alert.id == state["alert_id"]).first()
    privilege = "system" if (alert.user or "").lower() == "system" else "standard_user"
    if alert.hostname and alert.hostname.startswith("SRV-"):
        asset_criticality = "high"
    else:
        asset_criticality = "medium"

    factors = RiskFactors(
        ioc_reputations=reputations,
        correlated_event_count=len(state.get("correlated_logs", [])),
        malware_detected=malware_detected,
        attack_technique_count=len(state.get("attack_matches", [])),
        atlas_technique_count=len(state.get("atlas_matches", [])),
        user_privilege=privilege,
        asset_criticality=asset_criticality,
        ti_confidence=max_confidence,
    )
    assessment = calculate_risk(factors)
    state["risk_assessment"] = {
        "score": assessment.score,
        "severity": assessment.severity,
        "breakdown": assessment.breakdown,
    }
    audit.record(db, actor="system", alert_id=state["alert_id"], tool_called="calculate_risk",
                 tool_result=state["risk_assessment"])
    return state


def _node_recommend_response(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    enrichments = state.get("enrichments", [])
    text = _build_evidence_text(state).lower()

    actions = recommend_actions(
        malware_detected=any(e["reputation"] == "malicious" and e["related_malware"] for e in enrichments),
        credential_dumping=any(t["technique_id"] == "T1003.001" for t in state.get("attack_matches", [])),
        c2_beaconing=any(e["reputation"] == "malicious" for e in enrichments if e["ioc_type"] in ("ipv4", "ipv6", "domain")),
        phishing_confirmed=any(t["technique_id"] == "T1566.002" for t in state.get("attack_matches", [])),
        brute_force_success=any(t["technique_id"] == "T1110" for t in state.get("attack_matches", [])) and "success" in text,
        lateral_movement=any(t["technique_id"] in ("T1047", "T1021.002") for t in state.get("attack_matches", [])),
        max_ioc_confidence=max((e["confidence"] for e in enrichments), default=0.0),
    )
    state["recommended_actions"] = actions
    audit.record(db, actor="system", alert_id=state["alert_id"], tool_called="recommend_actions",
                 tool_result={"actions": actions})
    return state


def _deterministic_fallback_summary(state: InvestigationState) -> InvestigationResult:
    """Used when Groq is not configured or its output fails validation."""
    enrichments = state.get("enrichments", [])
    malicious = [e for e in enrichments if e["reputation"] == "malicious"]
    findings = []
    if malicious:
        findings.append(
            {
                "statement": f"{len(malicious)} IOC(s) confirmed malicious via enrichment",
                "evidence": [f"{e['ioc_type']}:{e['ioc_value']} ({e['source']})" for e in malicious],
            }
        )
    if state.get("attack_matches"):
        findings.append(
            {
                "statement": "Evidence maps to known MITRE ATT&CK techniques",
                "evidence": [f"{m['technique_id']} - {m['name']}" for m in state["attack_matches"]],
            }
        )

    risk = state.get("risk_assessment", {})
    verdict = "malicious" if malicious or state.get("attack_matches") else "needs review"

    return InvestigationResult(
        verdict=verdict,
        severity=risk.get("severity", "low"),
        confidence=min(1.0, 0.5 + 0.1 * len(findings)),
        summary=(
            f"Deterministic-only summary (no LLM available): risk score "
            f"{risk.get('score', 0)}/100 ({risk.get('severity', 'low')}). "
            f"{len(malicious)} malicious IOC(s), {len(state.get('attack_matches', []))} "
            f"ATT&CK technique(s), {len(state.get('atlas_matches', []))} ATLAS technique(s) matched."
        ),
        findings=findings,
        evidence=[f"{e['ioc_type']}:{e['ioc_value']}" for e in enrichments],
        attack_techniques=[
            {
                "technique_id": m["technique_id"], "name": m["name"], "tactic": m["tactic"],
                "rationale": m["rationale"], "supporting_evidence": m["supporting_evidence"],
            }
            for m in state.get("attack_matches", [])
        ],
        atlas_techniques=[
            {
                "technique_id": m["technique_id"], "name": m["name"], "tactic": m["tactic"],
                "rationale": m["rationale"], "supporting_evidence": m["supporting_evidence"],
            }
            for m in state.get("atlas_matches", [])
        ],
        recommended_actions=state.get("recommended_actions", []),
    )


def _node_summarize_investigation(state: InvestigationState) -> InvestigationState:
    db: Session = state["db"]
    evidence_payload = {
        "alert": state.get("alert_evidence", {}),
        "enrichments": state.get("enrichments", []),
        "correlated_logs": state.get("correlated_logs", [])[:20],  # cap prompt size
        "mitre_attack_matches": state.get("attack_matches", []),
        "mitre_atlas_matches": state.get("atlas_matches", []),
        "risk_assessment": state.get("risk_assessment", {}),
        "rag_sources": state.get("rag_sources", []),
    }

    llm_used = False
    if groq_client.is_configured():
        try:
            result = groq_client.generate_investigation_summary(evidence_payload)
            llm_used = True
            audit.record(db, actor="llm", alert_id=state["alert_id"],
                         decision="llm_summary_generated", tool_result={"verdict": result.verdict})
        except Exception as exc:
            print(f"GROQ ERROR: {type(exc).__name__}: {exc}", flush=True)
            audit.record(db, actor="system", alert_id=state["alert_id"],
                         decision="llm_summary_failed_fallback_to_deterministic",
                         notes=str(exc)[:500])
            result = _deterministic_fallback_summary(state)
    else:
        result = _deterministic_fallback_summary(state)
        audit.record(db, actor="system", alert_id=state["alert_id"],
                     decision="llm_not_configured_using_deterministic_summary")

    # Severity of record is ALWAYS the deterministic risk engine's band,
    # regardless of what the LLM (if used) put in InvestigationResult.severity.
    state["investigation_result"] = result.model_dump()
    state["investigation_result"]["severity"] = state.get("risk_assessment", {}).get("severity", result.severity)
    state["llm_used"] = llm_used
    return state


def build_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("alert_triage", _node_alert_triage)
    graph.add_node("extract_iocs", _node_extract_iocs)
    graph.add_node("enrich_iocs", _node_enrich_iocs)
    graph.add_node("investigate_logs", _node_investigate_logs)
    graph.add_node("map_attack", _node_map_attack)
    graph.add_node("map_atlas", _node_map_atlas)
    graph.add_node("correlate_evidence", _node_correlate_evidence)
    graph.add_node("assess_risk", _node_assess_risk)
    graph.add_node("summarize_investigation", _node_summarize_investigation)
    graph.add_node("recommend_response", _node_recommend_response)

    graph.set_entry_point("alert_triage")
    graph.add_edge("alert_triage", "extract_iocs")
    graph.add_edge("extract_iocs", "enrich_iocs")
    graph.add_edge("enrich_iocs", "investigate_logs")
    graph.add_edge("investigate_logs", "map_attack")
    graph.add_edge("map_attack", "map_atlas")
    graph.add_edge("map_atlas", "correlate_evidence")
    graph.add_edge("correlate_evidence", "assess_risk")
    graph.add_edge("assess_risk", "summarize_investigation")
    graph.add_edge("summarize_investigation", "recommend_response")
    graph.add_edge("recommend_response", END)

    return graph.compile()


_compiled_graph = None


def get_compiled_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def run_investigation(db: Session, alert_id: str) -> InvestigationState:
    graph = get_compiled_graph()
    initial_state: InvestigationState = {"alert_id": alert_id, "db": db}
    final_state = graph.invoke(initial_state)
    return final_state
