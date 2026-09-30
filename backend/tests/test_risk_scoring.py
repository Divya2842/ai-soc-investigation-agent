from app.services.risk.score import RiskFactors, calculate_risk


def test_all_clean_low_risk():
    factors = RiskFactors(ioc_reputations=["clean", "clean"], correlated_event_count=0)
    result = calculate_risk(factors)
    assert result.severity == "low"
    assert result.score < 25


def test_malicious_ioc_with_malware_is_high_or_critical():
    factors = RiskFactors(
        ioc_reputations=["malicious", "malicious"],
        correlated_event_count=5,
        malware_detected=True,
        attack_technique_count=2,
        user_privilege="system",
        asset_criticality="critical",
        ti_confidence=0.9,
    )
    result = calculate_risk(factors)
    assert result.severity in ("high", "critical")
    assert result.score > 50


def test_score_is_capped_at_100():
    factors = RiskFactors(
        ioc_reputations=["malicious"] * 20,
        correlated_event_count=999,
        malware_detected=True,
        attack_technique_count=99,
        atlas_technique_count=99,
        user_privilege="system",
        asset_criticality="critical",
        ti_confidence=1.0,
    )
    result = calculate_risk(factors)
    assert result.score <= 100


def test_breakdown_sums_reasonably_to_score():
    factors = RiskFactors(ioc_reputations=["suspicious"], correlated_event_count=2)
    result = calculate_risk(factors)
    assert abs(sum(result.breakdown.values()) - result.score) < 0.01


def test_severity_deterministic_not_llm_influenced():
    # Same factors always produce the same severity -- no randomness.
    factors = RiskFactors(ioc_reputations=["malicious"], malware_detected=True)
    r1 = calculate_risk(factors)
    r2 = calculate_risk(factors)
    assert r1.severity == r2.severity
    assert r1.score == r2.score
