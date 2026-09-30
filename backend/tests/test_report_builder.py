from app.services.reporting.report_builder import (
    NOT_AVAILABLE,
    NO_ATLAS_MESSAGE,
    ReportInputs,
    build_analyst_report,
    build_customer_escalation,
    classify,
)


def _base_inputs(**overrides) -> ReportInputs:
    defaults = dict(
        alert_id="ALRT-1",
        alert_name="Test Alert",
        detection_time="2026-09-08T14:22:11+00:00",
        affected_user=None,
        affected_host=None,
        priority="high",
        source="EDR",
        description=None,
        correlated_event_count=0,
        user_activity_reviewed=False,
        device_activity_reviewed=False,
        verdict="unknown",
        llm_summary="",
        llm_used=False,
        findings=[],
        iocs=[],
        attack_techniques=[],
        atlas_techniques=[],
        risk_score=0.0,
        severity="low",
        confidence=0.0,
        recommended_actions=[],
    )
    defaults.update(overrides)
    return ReportInputs(**defaults)


def test_true_positive_requires_malicious_ioc_and_technique():
    inputs = _base_inputs(
        iocs=[{"value": "1.2.3.4", "ioc_type": "ipv4", "reputation": "malicious"}],
        attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        confidence=0.9,
    )
    result = classify(inputs)
    assert result.disposition == "true_positive"
    assert result.requires_customer_validation is False  # high confidence TP


def test_low_confidence_tp_still_requires_validation():
    inputs = _base_inputs(
        iocs=[{"value": "1.2.3.4", "ioc_type": "ipv4", "reputation": "malicious"}],
        attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        confidence=0.3,
    )
    result = classify(inputs)
    assert result.disposition == "true_positive"
    assert result.requires_customer_validation is True


def test_false_positive_when_all_clean_and_no_techniques():
    inputs = _base_inputs(
        iocs=[{"value": "8.8.8.8", "ioc_type": "ipv4", "reputation": "unknown"}],
        attack_techniques=[],
    )
    result = classify(inputs)
    assert result.disposition == "false_positive"
    assert result.requires_customer_validation is False


def test_inconclusive_when_no_evidence_at_all():
    inputs = _base_inputs(iocs=[], attack_techniques=[], atlas_techniques=[])
    result = classify(inputs)
    assert result.disposition == "inconclusive"


def test_suspicious_when_technique_but_no_malicious_ioc():
    inputs = _base_inputs(
        iocs=[{"value": "8.8.8.8", "ioc_type": "ipv4", "reputation": "unknown"}],
        attack_techniques=[{"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    )
    result = classify(inputs)
    assert result.disposition == "suspicious"
    assert result.requires_customer_validation is True


def test_disposition_not_derived_from_risk_score_alone():
    # Two identical risk scores, different underlying evidence composition
    # -> different dispositions. This is the whole point of the rule.
    tp_inputs = _base_inputs(
        risk_score=50.0,
        iocs=[{"value": "1.2.3.4", "ioc_type": "ipv4", "reputation": "malicious"}],
        attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        confidence=0.9,
    )
    suspicious_inputs = _base_inputs(
        risk_score=50.0,
        iocs=[{"value": "8.8.8.8", "ioc_type": "ipv4", "reputation": "unknown"}],
        attack_techniques=[{"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}],
    )
    assert classify(tp_inputs).disposition != classify(suspicious_inputs).disposition


def test_report_uses_not_available_for_missing_fields():
    inputs = _base_inputs(affected_user=None, affected_host=None, description=None)
    classification = classify(inputs)
    report = build_analyst_report(inputs, classification)
    assert f"Affected User: {NOT_AVAILABLE}" in report
    assert f"Affected Host: {NOT_AVAILABLE}" in report
    assert f"Description: {NOT_AVAILABLE}" in report


def test_report_never_omits_no_atlas_message():
    inputs = _base_inputs(atlas_techniques=[])
    classification = classify(inputs)
    report = build_analyst_report(inputs, classification)
    assert NO_ATLAS_MESSAGE in report


def test_report_never_leaks_rag_terminology():
    inputs = _base_inputs(
        iocs=[{"value": "1.2.3.4", "ioc_type": "ipv4", "reputation": "malicious"}],
        attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
    )
    classification = classify(inputs)
    report = build_analyst_report(inputs, classification)
    for banned in ("rag", "retrieval", "vector", "playbook", "knowledge_base", "source_document"):
        assert banned not in report.lower()


def test_customer_escalation_has_required_sections():
    inputs = _base_inputs(
        affected_user="j.doe",
        affected_host="WKS-01",
        iocs=[{"value": "1.2.3.4", "ioc_type": "ipv4", "reputation": "malicious"}],
        attack_techniques=[{"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
        confidence=0.4,
    )
    classification = classify(inputs)
    report = build_customer_escalation(inputs, classification)
    for required in (
        "Hi Team,", "Summary:", "Disposition:", "Confidence:", "Impact/Risk:",
        "Customer Action Items:", "Recommended Other Actions:", "Key Findings:",
        "Other Investigation Details:",
    ):
        assert required in report
