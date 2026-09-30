"""
Deterministic report generation.

This module builds the analyst-facing investigation report and the
customer-validation escalation format directly from evidence already
persisted on the Investigation/Alert/IOC rows.

The report does not call the LLM directly.

The LLM's free-text summary/findings, when available, can be included
as supporting narrative, while classification remains deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress


NOT_AVAILABLE = "Not available in the collected evidence."
NO_ATLAS_MESSAGE = "No ATLAS mapping identified from the collected evidence."


DISPOSITION_LABELS = {
    "true_positive": "TP (True Positive)",
    "false_positive": "FP (False Positive)",
    "benign_positive": "BP (Benign Positive)",
    "suspicious": "Suspicious",
    "inconclusive": "Inconclusive",
}


@dataclass
class ReportInputs:
    """
    Everything the report builder needs.

    IOC dictionaries can contain:

    value
    ioc_type
    reputation
    country
    isp
    created_year
    owner
    digitally_signed_by
    """

    alert_id: str
    alert_name: str
    detection_time: str | None
    affected_user: str | None
    affected_host: str | None
    priority: str
    source: str
    description: str | None

    correlated_event_count: int
    user_activity_reviewed: bool
    device_activity_reviewed: bool

    verdict: str
    llm_summary: str
    llm_used: bool

    findings: list[dict] = field(default_factory=list)

    iocs: list[dict] = field(default_factory=list)

    attack_techniques: list[dict] = field(default_factory=list)
    atlas_techniques: list[dict] = field(default_factory=list)

    risk_score: float = 0.0
    severity: str = "low"
    confidence: float = 0.0

    recommended_actions: list[str] = field(default_factory=list)


@dataclass
class Classification:
    disposition: str
    requires_customer_validation: bool
    impact: str
    closure_reason: str


def classify(inputs: ReportInputs) -> Classification:
    """
    Deterministic disposition classification.

    Classification is based on the actual evidence composition,
    not simply the numeric risk score.
    """

    malicious_iocs = [
        i
        for i in inputs.iocs
        if i.get("reputation") == "malicious"
    ]

    suspicious_iocs = [
        i
        for i in inputs.iocs
        if i.get("reputation") == "suspicious"
    ]

    unknown_or_no_data = all(
        i.get("reputation") in ("unknown", None)
        for i in inputs.iocs
    )

    has_techniques = (
        bool(inputs.attack_techniques)
        or bool(inputs.atlas_techniques)
    )

    if malicious_iocs and has_techniques:

        disposition = "true_positive"

        impact = (
            f"Confirmed malicious activity involving "
            f"{len(malicious_iocs)} IOC(s) and "
            f"{len(inputs.attack_techniques)} matched "
            f"ATT&CK technique(s)."
        )

        closure_reason = (
            "Evidence confirms malicious indicators and "
            "adversary technique(s) on the affected asset."
        )

        requires_validation = inputs.confidence < 0.6

    elif malicious_iocs or (has_techniques and suspicious_iocs):

        disposition = (
            "true_positive"
            if malicious_iocs
            else "suspicious"
        )

        impact = (
            f"{len(malicious_iocs)} malicious and "
            f"{len(suspicious_iocs)} suspicious IOC(s) identified; "
            f"technique correlation is partial."
        )

        closure_reason = (
            "Evidence shows a credible but not fully "
            "corroborated indicator of compromise."
        )

        requires_validation = True

    elif has_techniques and not malicious_iocs and not suspicious_iocs:

        disposition = "suspicious"

        impact = (
            "Technique-level evidence detected without "
            "corroborating malicious IOC reputation."
        )

        closure_reason = (
            "Behavioral pattern matches a known technique, "
            "but no malicious indicator confirms intent."
        )

        requires_validation = True

    elif not inputs.iocs and not has_techniques:

        disposition = "inconclusive"

        impact = NOT_AVAILABLE

        closure_reason = (
            "Insufficient evidence was collected to confirm "
            "or rule out malicious activity."
        )

        requires_validation = True

    elif unknown_or_no_data and not has_techniques:

        disposition = "false_positive"

        impact = (
            "No confirmed malicious indicators or techniques "
            "were identified from the collected evidence."
        )

        closure_reason = (
            "All collected IOCs returned clean/unknown reputation "
            "and no technique evidence was found."
        )

        requires_validation = False

    else:

        disposition = "inconclusive"

        impact = NOT_AVAILABLE

        closure_reason = (
            "Evidence collected does not clearly support "
            "a definitive classification."
        )

        requires_validation = True

    return Classification(
        disposition=disposition,
        requires_customer_validation=requires_validation,
        impact=impact,
        closure_reason=closure_reason,
    )


def _line_or_na(
    label: str,
    value: str | None,
) -> str:
    """
    Format a normal report field.
    """

    return f"- {label}: {value if value else NOT_AVAILABLE}"


def _format_ioc_line(ioc: dict) -> str:
    """Show the IOC and only enrichment fields that actually have data."""
    ioc_type = str(ioc.get("ioc_type") or "").strip().lower()
    value = ioc.get("value") or "No details"
    label = {"ipv4":"IP Address","ipv6":"IP Address","md5":"Hash","sha1":"Hash","sha256":"Hash","hash":"Hash","domain":"Domain","url":"URL","email":"Email"}.get(ioc_type, "IOC")
    lines = [f"- {label}: {value}"]
    if ioc_type in ("ipv4", "ipv6"):
        try:
            if ipaddress.ip_address(value).is_private:
                return "\n".join(lines + ["  Type: Private IP", "  Reputation: Not applicable"])
        except ValueError:
            pass
    fields = []
    reputation = ioc.get("reputation")
    if reputation and reputation not in ("unknown", "not_available"):
        fields.append(("Reputation", reputation))
    if ioc_type in ("ipv4", "ipv6"):
        fields += [("Country", ioc.get("country")), ("ISP", ioc.get("isp"))]
    elif ioc_type in ("md5", "sha1", "sha256", "hash"):
        fields += [("Digitally Signed By", ioc.get("digitally_signed_by"))]
    elif ioc_type == "domain":
        fields += [("Domain Created", ioc.get("created_year")), ("Domain Owner", ioc.get("owner"))]
    available = [(k,v) for k,v in fields if v not in (None, "", [], {})]
    if not available and len(lines) == 1 and not reputation:
        lines.append("  No details")
    else:
        lines.extend(f"  {k}: {v}" for k,v in available)
    return "\n".join(lines)

def build_analyst_report(
    inputs: ReportInputs,
    classification: Classification,
) -> str:

    lines: list[str] = []

    # =========================================================
    # INCIDENT SUMMARY
    # =========================================================

    lines.append("Incident Summary")
    lines.append("")

    if inputs.llm_used and inputs.llm_summary:

        lines.append(
            inputs.llm_summary
        )

    else:

        lines.append(
            f"Deterministic evidence-based summary: "
            f"risk score {inputs.risk_score}/100 "
            f"({inputs.severity}); "
            f"{len(inputs.iocs)} IOC(s) collected, "
            f"{len(inputs.attack_techniques)} ATT&CK technique(s) "
            f"and {len(inputs.atlas_techniques)} ATLAS technique(s) "
            f"matched."
        )

    lines.append("")

    # =========================================================
    # ENTITY DETAILS
    # =========================================================

    lines.append("1. Entity Details")
    lines.append("")

    lines.append(
        _line_or_na(
            "Alert Name",
            inputs.alert_name,
        )
    )

    lines.append(
        _line_or_na(
            "Alert ID",
            inputs.alert_id,
        )
    )

    lines.append(
        _line_or_na(
            "Detection Time",
            inputs.detection_time,
        )
    )

    lines.append(
        _line_or_na(
            "Affected User",
            inputs.affected_user,
        )
    )

    lines.append(
        _line_or_na(
            "Affected Host",
            inputs.affected_host,
        )
    )

    lines.append(
        _line_or_na(
            "Priority/Severity",
            inputs.priority,
        )
    )

    lines.append(
        _line_or_na(
            "Source",
            inputs.source,
        )
    )

    lines.append(
        _line_or_na(
            "Description",
            inputs.description,
        )
    )

    lines.append("")

    # =========================================================
    # KEY FINDINGS
    # =========================================================

    lines.append("2. Key Findings")
    lines.append("")

    if inputs.correlated_event_count:

        lines.append(
            f"- Logs reviewed: "
            f"{inputs.correlated_event_count} "
            f"correlated event(s)"
        )

    else:

        lines.append(
            f"- Logs reviewed: {NOT_AVAILABLE}"
        )

    if inputs.user_activity_reviewed:

        lines.append(
            "- User activity validation: "
            "reviewed against correlated logs"
        )

    else:

        lines.append(
            f"- User activity validation: "
            f"{NOT_AVAILABLE}"
        )

    if inputs.device_activity_reviewed:

        lines.append(
            "- Device activity: "
            "reviewed against correlated host logs"
        )

    else:

        lines.append(
            f"- Device activity: "
            f"{NOT_AVAILABLE}"
        )

    if inputs.iocs:

        lines.append(
            f"- Threat intelligence: "
            f"{len(inputs.iocs)} IOC(s) enriched "
            f"(see section 3)"
        )

    else:

        lines.append(
            f"- Threat intelligence: "
            f"{NOT_AVAILABLE}"
        )

    if inputs.findings:

        for finding in inputs.findings:

            statement = finding.get(
                "statement",
                "",
            )

            evidence = finding.get(
                "evidence",
                [],
            )

            if evidence:

                lines.append(
                    f"- {statement} "
                    f"(evidence: {'; '.join(evidence)})"
                )

            else:

                lines.append(
                    f"- {statement}"
                )

    if inputs.recommended_actions:

        lines.append(
            "- Actions taken/recommended: "
            + ", ".join(inputs.recommended_actions)
        )

    else:

        lines.append(
            f"- Actions taken: {NOT_AVAILABLE}"
        )

    lines.append("")

    # =========================================================
    # IOC / THREAT INTELLIGENCE
    # =========================================================

    lines.append(
        "3. IOC / Threat Intelligence Findings"
    )

    lines.append("")

    if inputs.iocs:

        for ioc in inputs.iocs:

            lines.append(
                _format_ioc_line(ioc)
            )

            lines.append("")

    else:

        lines.append(
            f"- {NOT_AVAILABLE}"
        )

    # =========================================================
    # MITRE ATT&CK / ATLAS
    # =========================================================

    lines.append(
        "4. MITRE ATT&CK / ATLAS Mapping"
    )

    lines.append("")

    lines.append(
        "MITRE ATT&CK:"
    )

    if inputs.attack_techniques:

        for technique in inputs.attack_techniques:

            lines.append(
                f"- {technique['technique_id']} "
                f"— {technique['name']} "
                f"({technique['tactic']})"
            )

    else:

        lines.append(
            f"- {NOT_AVAILABLE}"
        )

    lines.append("")

    lines.append(
        "MITRE ATLAS:"
    )

    if inputs.atlas_techniques:

        for technique in inputs.atlas_techniques:

            lines.append(
                f"- {technique['technique_id']} "
                f"— {technique['name']} "
                f"({technique.get('tactic', NOT_AVAILABLE)})"
            )

    else:

        lines.append(
            f"- {NO_ATLAS_MESSAGE}"
        )

    lines.append("")

    # =========================================================
    # CONCLUSION
    # =========================================================

    lines.append("5. Conclusion")
    lines.append("")

    lines.append(
        f"- Classification/Disposition: "
        f"{DISPOSITION_LABELS[classification.disposition]}"
    )

    lines.append(
        f"- Impact: "
        f"{classification.impact}"
    )

    lines.append(
        f"- Closure Reason: "
        f"{classification.closure_reason}"
    )

    lines.append(
        f"- Confidence: "
        f"{round(inputs.confidence * 100)}%"
    )

    lines.append("")

    # =========================================================
    # RECOMMENDED ACTIONS
    # =========================================================

    lines.append("6. Recommended Actions")
    lines.append("")

    if inputs.recommended_actions:

        for action in inputs.recommended_actions:

            lines.append(
                f"- {action}"
            )

    else:

        lines.append(
            "- No specific actions are recommended "
            "based on the collected evidence."
        )

    lines.append("")

    # =========================================================
    # OTHER INVESTIGATION DETAILS
    # =========================================================

    lines.append("7. Other Investigation Details")
    lines.append("")

    lines.append(
        f"- Deterministic risk score: "
        f"{inputs.risk_score}/100 "
        f"({inputs.severity})"
    )

    if inputs.llm_used:

        lines.append(
            "- AI-authored narrative summary was used "
            "for the Incident Summary above."
        )

    else:

        lines.append(
            "- AI generation was unavailable for this "
            "investigation; this report is fully deterministic."
        )

    return "\n".join(lines)


def build_customer_escalation(
    inputs: ReportInputs,
    classification: Classification,
) -> str:

    lines: list[str] = []

    lines.append("Hi Team")
    lines.append("")

    lines.append("Summary:")
    lines.append("")

    if inputs.llm_used and inputs.llm_summary:

        lines.append(
            inputs.llm_summary
        )

    else:

        lines.append(
            f"Investigation of alert "
            f"{inputs.alert_id} "
            f"({inputs.alert_name}) found "
            f"{len(inputs.iocs)} IOC(s) and "
            f"{len(inputs.attack_techniques)} "
            f"matched ATT&CK technique(s)."
        )

    lines.append("")

    lines.append(
        f"Disposition: "
        f"{DISPOSITION_LABELS[classification.disposition]}"
    )

    lines.append("")

    lines.append(
        f"Confidence: "
        f"{round(inputs.confidence * 100)}%"
    )

    lines.append("")

    lines.append(
        f"Impact/Risk: "
        f"{classification.impact}"
    )

    lines.append("")

    lines.append("Customer Action Items:")
    lines.append("")

    if classification.requires_customer_validation:

        lines.append(
            "- Please confirm whether the affected "
            "user/host activity described below was authorized."
        )

        if inputs.affected_user:

            lines.append(
                f"- Verify recent activity for user: "
                f"{inputs.affected_user}"
            )

        if inputs.affected_host:

            lines.append(
                f"- Verify recent activity for host: "
                f"{inputs.affected_host}"
            )

    else:

        lines.append(
            "- No customer action required at this time."
        )

    lines.append("")

    lines.append("Recommended Other Actions:")
    lines.append("")

    if inputs.recommended_actions:

        for action in inputs.recommended_actions:

            lines.append(
                f"- {action}"
            )

    else:

        lines.append(
            f"- {NOT_AVAILABLE}"
        )

    lines.append("")

    lines.append("Key Findings:")
    lines.append("")

    if inputs.findings:

        for finding in inputs.findings:

            lines.append(
                f"- {finding.get('statement', '')}"
            )

    elif inputs.iocs:

        for ioc in inputs.iocs[:5]:

            lines.append(
                f"- {ioc.get('value')} "
                f"({ioc.get('ioc_type')}): "
                f"{ioc.get('reputation') or 'unknown'}"
            )

    else:

        lines.append(
            f"- {NOT_AVAILABLE}"
        )

    lines.append("")

    lines.append(
        "Other Investigation Details:"
    )

    lines.append(
        f"- Risk score: "
        f"{inputs.risk_score}/100 "
        f"({inputs.severity})"
    )

    return "\n".join(lines)