from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    verdict: str
    status: str
    disposition: str
    requires_customer_validation: bool
    severity: str
    risk_score: float
    risk_factors: dict[str, Any]
    confidence: float
    summary: str
    findings: list[dict[str, Any]]
    evidence: list[str]
    attack_techniques: list[dict[str, Any]]
    atlas_techniques: list[dict[str, Any]]
    recommended_actions: list[str]
    # NOTE: rag_sources is intentionally NOT exposed here. RAG retrieval is
    # used internally to help ground the LLM's summary (see
    # agents/investigation_graph.py) but source documents/playbook names
    # are internal retrieval metadata, not investigation findings, and must
    # never reach the analyst-facing report or frontend.
    llm_used: bool
    created_at: datetime


class InvestigationReportOut(BaseModel):
    format: str  # "analyst" | "customer"
    report_markdown: str


class ResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    action_type: str
    status: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    simulated_result: str | None = None
    created_at: datetime


class ApproveRejectRequest(BaseModel):
    approved_by: str = "analyst"
