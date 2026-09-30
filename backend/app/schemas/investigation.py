from __future__ import annotations

from pydantic import BaseModel, Field


class AttackTechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactic: str
    rationale: str
    supporting_evidence: list[str] = Field(default_factory=list)


class AtlasTechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactic: str
    rationale: str
    supporting_evidence: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Every finding must cite the evidence it's based on. No free-floating claims."""

    statement: str
    evidence: list[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    """
    The ONLY shape an LLM response is allowed to take in this application.
    `severity` here is descriptive of the LLM's read on the situation, but
    it is NOT the value persisted as the investigation's severity of
    record -- `services/risk/score.py`'s deterministic score is the source
    of truth for that (see `Investigation.risk_score` / `Investigation.severity`).
    """

    verdict: str  # e.g. "malicious", "benign", "suspicious - needs review"
    severity: str  # low | medium | high | critical (LLM's own read, informational only)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechniqueOut] = Field(default_factory=list)
    atlas_techniques: list[AtlasTechniqueOut] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
