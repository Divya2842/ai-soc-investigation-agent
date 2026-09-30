"""
Deterministic risk scoring.

This module is the single source of truth for an investigation's severity.
The LLM may explain why the score is what it is, but it never sets it.
Score is a weighted 0-100 value mapped to Low/Medium/High/Critical bands.
"""
from __future__ import annotations

from dataclasses import dataclass, field

REPUTATION_WEIGHTS = {"malicious": 30, "suspicious": 12, "clean": 0, "unknown": 3}
PRIVILEGE_WEIGHTS = {"system": 15, "admin": 12, "service_account": 8, "standard_user": 0}
ASSET_CRITICALITY_WEIGHTS = {"critical": 20, "high": 12, "medium": 6, "low": 0}


@dataclass
class RiskFactors:
    ioc_reputations: list[str] = field(default_factory=list)  # one per enriched IOC
    correlated_event_count: int = 0
    malware_detected: bool = False
    attack_technique_count: int = 0
    atlas_technique_count: int = 0
    user_privilege: str = "standard_user"  # system|admin|service_account|standard_user
    asset_criticality: str = "medium"  # critical|high|medium|low
    ti_confidence: float = 0.0  # 0.0-1.0, max confidence across enrichments


@dataclass
class RiskAssessment:
    score: float  # 0-100
    severity: str  # low|medium|high|critical
    factors: RiskFactors
    breakdown: dict[str, float]


def _band(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def calculate_risk(factors: RiskFactors) -> RiskAssessment:
    breakdown: dict[str, float] = {}

    ioc_score = sum(REPUTATION_WEIGHTS.get(r, 0) for r in factors.ioc_reputations)
    ioc_score = min(ioc_score, 40)  # cap so a single alert with many IOCs doesn't dominate
    breakdown["ioc_reputation"] = ioc_score

    correlation_score = min(factors.correlated_event_count * 3, 15)
    breakdown["event_correlation"] = correlation_score

    malware_score = 20.0 if factors.malware_detected else 0.0
    breakdown["malware_detection"] = malware_score

    technique_score = min(
        factors.attack_technique_count * 5 + factors.atlas_technique_count * 5, 20
    )
    breakdown["mitre_techniques"] = technique_score

    privilege_score = PRIVILEGE_WEIGHTS.get(factors.user_privilege, 0)
    breakdown["user_privilege"] = privilege_score

    asset_score = ASSET_CRITICALITY_WEIGHTS.get(factors.asset_criticality, 0)
    breakdown["asset_criticality"] = asset_score

    ti_score = factors.ti_confidence * 10
    breakdown["threat_intel_confidence"] = round(ti_score, 2)

    total = sum(breakdown.values())
    total = max(0.0, min(100.0, total))

    return RiskAssessment(score=round(total, 2), severity=_band(total), factors=factors, breakdown=breakdown)
