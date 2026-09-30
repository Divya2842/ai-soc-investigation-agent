from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.agents.investigation_graph import run_investigation
from app.database.session import get_db
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.ioc import IOC
from app.models.ioc_enrichment import IOCEnrichment
from app.models.response_action import ResponseAction
from app.schemas.investigation_out import InvestigationOut, InvestigationReportOut
from app.services import audit
from app.services.reporting.report_builder import (
    ReportInputs,
    build_analyst_report,
    build_customer_escalation,
    classify,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["investigations"])


def _latest_enrichment_for(
    db: Session,
    ioc_id: str,
) -> IOCEnrichment | None:
    return (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id)
        .order_by(IOCEnrichment.enriched_at.desc())
        .first()
    )


def _gather_report_inputs(
    db: Session,
    alert: Alert,
    investigation: Investigation,
) -> ReportInputs:
    iocs = db.query(IOC).filter(IOC.alert_id == alert.id).all()

    ioc_dicts = []

    for ioc in iocs:
        enrichment = _latest_enrichment_for(db, ioc.id)

        ioc_dicts.append(
            {
                "value": ioc.value,
                "ioc_type": ioc.ioc_type,
                "reputation": (
                    enrichment.reputation
                    if enrichment
                    else None
                ),
                "country": (
                    enrichment.country
                    if enrichment
                    else None
                ),
                "isp": (
                    enrichment.isp
                    if enrichment
                    else None
                ),
                "created_year": (
                    enrichment.created_year
                    if enrichment
                    else None
                ),
                "owner": (
                    enrichment.owner
                    if enrichment
                    else None
                ),
                "digitally_signed_by": (
                    enrichment.digitally_signed_by
                    if enrichment
                    else None
                ),
            }
        )

    return ReportInputs(
        alert_id=alert.alert_id,
        alert_name=alert.alert_name,
        detection_time=(
            alert.timestamp.isoformat()
            if alert.timestamp
            else None
        ),
        affected_user=alert.user,
        affected_host=alert.hostname,
        priority=alert.severity,
        source=alert.source,
        description=alert.description,
        correlated_event_count=investigation.risk_factors.get(
            "correlated_event_count",
            0,
        ),
        user_activity_reviewed=bool(alert.user),
        device_activity_reviewed=bool(alert.hostname),
        verdict=investigation.verdict,
        llm_summary=investigation.summary,
        llm_used=investigation.llm_used,
        findings=investigation.findings,
        iocs=ioc_dicts,
        attack_techniques=investigation.attack_techniques,
        atlas_techniques=investigation.atlas_techniques,
        risk_score=investigation.risk_score,
        severity=investigation.severity,
        confidence=investigation.confidence,
        recommended_actions=investigation.recommended_actions,
    )


def _run_and_persist(
    db: Session,
    alert: Alert,
) -> Investigation:
    alert.status = "investigating"
    db.commit()

    try:
        final_state = run_investigation(db, alert.id)
        result = final_state["investigation_result"]
        risk = final_state.get("risk_assessment", {})
    except Exception as exc:
        logger.exception(
            "Investigation failed for alert %s",
            alert.id,
        )

        alert.status = "investigation_failed"
        db.commit()

        audit.record(
            db,
            actor="system",
            alert_id=alert.id,
            decision="investigation_failed",
            notes=str(exc)[:500],
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Investigation failed unexpectedly. The alert itself was "
                "not affected and its status has been set to "
                "'investigation_failed'. See server logs / audit log "
                "for details."
            ),
        ) from exc

    risk_factors = dict(
        risk.get("breakdown", {})
    )

    risk_factors["correlated_event_count"] = len(
        final_state.get("correlated_logs", [])
    )

    investigation = Investigation(
        alert_id=alert.id,
        verdict=result["verdict"],
        status="completed",
        severity=risk.get(
            "severity",
            result["severity"],
        ),
        risk_score=risk.get("score", 0.0),
        risk_factors=risk_factors,
        confidence=result["confidence"],
        summary=result["summary"],
        findings=result["findings"],
        evidence=result["evidence"],
        attack_techniques=result["attack_techniques"],
        atlas_techniques=result["atlas_techniques"],
        recommended_actions=final_state.get(
            "recommended_actions",
            [],
        ),
        rag_sources=final_state.get(
            "rag_sources",
            [],
        ),
        llm_used=final_state.get(
            "llm_used",
            False,
        ),
    )

    db.add(investigation)
    db.flush()

    report_inputs = _gather_report_inputs(
        db,
        alert,
        investigation,
    )

    classification = classify(report_inputs)

    investigation.disposition = (
        classification.disposition
    )

    investigation.requires_customer_validation = (
        classification.requires_customer_validation
    )

    investigation.report_markdown = build_analyst_report(
        report_inputs,
        classification,
    )

    alert.status = "investigated"

    db.commit()
    db.refresh(investigation)

    for action_text in investigation.recommended_actions:
        if (
            action_text.lower().startswith("recommend")
            and "monitoring" not in action_text.lower()
        ):
            db.add(
                ResponseAction(
                    investigation_id=investigation.id,
                    action_type=action_text,
                )
            )

    db.commit()

    audit.record(
        db,
        actor="system",
        alert_id=alert.id,
        investigation_id=investigation.id,
        decision="investigation_complete",
        tool_result={
            "verdict": investigation.verdict,
            "severity": investigation.severity,
            "disposition": investigation.disposition,
        },
    )

    return investigation


@router.post(
    "/api/alerts/{alert_db_id}/investigate",
    response_model=InvestigationOut,
    status_code=201,
)
def investigate_alert(
    alert_db_id: str,
    db: Session = Depends(get_db),
) -> Investigation:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_db_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="alert not found",
        )

    return _run_and_persist(db, alert)


@router.post(
    "/api/investigations",
    response_model=InvestigationOut,
    status_code=201,
)
def create_investigation(
    alert_id: str,
    db: Session = Depends(get_db),
) -> Investigation:
    """Alternate entry point: POST /api/investigations?alert_id=<internal alert id>."""

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="alert not found",
        )

    return _run_and_persist(db, alert)


@router.get(
    "/api/investigations/{investigation_id}",
    response_model=InvestigationOut,
)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> Investigation:
    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id
        )
        .first()
    )

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="investigation not found",
        )

    return investigation


@router.get(
    "/api/investigations/{investigation_id}/report",
    response_model=InvestigationReportOut,
)
def get_investigation_report(
    investigation_id: str,
    format: str = Query(
        default="analyst",
        pattern="^(analyst|customer)$",
    ),
    db: Session = Depends(get_db),
) -> InvestigationReportOut:
    """
    Returns the structured investigation report.

    format=analyst:
        Full evidence-based analyst report.

    format=customer:
        Shorter customer-validation escalation report.
    """

    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id
        )
        .first()
    )

    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="investigation not found",
        )

    alert = (
        db.query(Alert)
        .filter(
            Alert.id == investigation.alert_id
        )
        .first()
    )

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="alert for this investigation not found",
        )

    if format == "analyst":
        return InvestigationReportOut(
            format="analyst",
            report_markdown=investigation.report_markdown,
        )

    report_inputs = _gather_report_inputs(
        db,
        alert,
        investigation,
    )

    classification = classify(report_inputs)

    return InvestigationReportOut(
        format="customer",
        report_markdown=build_customer_escalation(
            report_inputs,
            classification,
        ),
    )