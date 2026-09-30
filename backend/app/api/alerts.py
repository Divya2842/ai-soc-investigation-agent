from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database.session import get_db, get_session_factory
from app.models.alert import Alert
from app.models.investigation import Investigation
from app.models.ioc import IOC
from app.models.ioc_enrichment import IOCEnrichment
from app.schemas.alert import (
    AlertCreate,
    AlertCreateResponse,
    AlertDetailOut,
    AlertOut,
    AlertStatsOut,
    IOCOut,
    IOCWithEnrichmentOut,
)
from app.services.ioc.enrichment.service import enrich_alert_iocs_background
from app.services.ioc.extract import extract_iocs

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# Fields the global search box matches against. Kept as a single list so
# the search implementation and its documentation can't drift apart.
_SEARCHABLE_FIELDS = (
    "alert_id",
    "alert_name",
    "source",
    "user",
    "hostname",
    "source_ip",
    "destination_ip",
    "domain",
    "url",
    "file_hash",
    "description",
)


@router.post("", response_model=AlertCreateResponse, status_code=201)
def create_alert(
    payload: AlertCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    session_factory=Depends(get_session_factory),
) -> AlertCreateResponse:
    existing = db.query(Alert).filter(Alert.alert_id == payload.alert_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"alert_id '{payload.alert_id}' already exists")

    alert = Alert(
        alert_id=payload.alert_id,
        alert_name=payload.alert_name,
        severity=payload.severity,
        timestamp=payload.timestamp,
        source=payload.source,
        user=payload.user,
        hostname=payload.hostname,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        command_line=payload.command_line,
        file_hash=payload.file_hash,
        domain=payload.domain,
        url=payload.url,
        description=payload.description,
        raw_event=payload.raw_event,
    )
    db.add(alert)
    db.flush()  # get alert.id without a full commit yet

    extracted = extract_iocs(
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        domain=alert.domain,
        url=alert.url,
        file_hash=alert.file_hash,
        command_line=alert.command_line,
        description=alert.description,
        raw_event=alert.raw_event,
    )
    ioc_rows = [IOC(alert_id=alert.id, ioc_type=i.ioc_type, value=i.value) for i in extracted]
    db.add_all(ioc_rows)
    db.commit()
    db.refresh(alert)
    for row in ioc_rows:
        db.refresh(row)
        row.alert_display_id = alert.alert_id  # for IOCOut.alert_display_id

    # Automatic IOC enrichment: kicked off in the background so external
    # provider latency (VirusTotal, AbuseIPDB) never blocks the alert-creation
    # response. No Celery/Redis -- FastAPI's BackgroundTasks is sufficient
    # for this workload and avoids unnecessary infrastructure. If enrichment
    # fails for any reason, the alert itself is already committed and
    # unaffected (see services/ioc/enrichment/service.py).
    if ioc_rows:
        background_tasks.add_task(
            enrich_alert_iocs_background, session_factory, alert.id, [row.id for row in ioc_rows]
        )

    return AlertCreateResponse(
        id=alert.id,
        alert_id=alert.alert_id,
        status=alert.status,
        extracted_iocs=[IOCOut.model_validate(row) for row in ioc_rows],
    )


@router.get("", response_model=list[AlertOut])
def list_alerts(
    response: Response,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    search: str | None = Query(
        default=None,
        description="Matches across alert ID, name, source, user, hostname, IPs, domain, URL, and file hash",
    ),
    start_date: datetime | None = Query(default=None, description="Only alerts detected at/after this timestamp"),
    end_date: datetime | None = Query(default=None, description="Only alerts detected at/before this timestamp"),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[Alert]:
    """
    Backend-side search/filter/pagination -- the frontend never loads the
    full alert table to filter client-side. The total row count (before
    pagination) is returned in the `X-Total-Count` response header so the
    response body stays a plain array for backward compatibility with
    existing API consumers.
    """
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if search:
        like = f"%{search}%"
        q = q.filter(or_(*(getattr(Alert, field).ilike(like) for field in _SEARCHABLE_FIELDS)))
    if start_date:
        q = q.filter(Alert.timestamp >= start_date)
    if end_date:
        q = q.filter(Alert.timestamp <= end_date)

    total = q.count()
    response.headers["X-Total-Count"] = str(total)

    return q.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/stats", response_model=AlertStatsOut)
def get_alert_stats(db: Session = Depends(get_db)) -> AlertStatsOut:
    """
    Dashboard counts, computed live from the database every call -- never
    hardcoded. "Investigated" counts alerts with at least one *completed*
    investigation actually persisted (not merely "in progress"), per the
    project's definition of that term.
    """
    total = db.query(Alert).count()
    counts_by_severity = {
        severity: db.query(Alert).filter(Alert.severity == severity).count()
        for severity in ("critical", "high", "medium", "low", "informational")
    }
    investigated = (
        db.query(Investigation.alert_id)
        .filter(Investigation.status == "completed")
        .distinct()
        .count()
    )
    return AlertStatsOut(total=total, investigated=investigated, **counts_by_severity)


def _attach_latest_enrichment(db: Session, iocs: list[IOC], alert_display_id: str | None = None) -> None:
    """Sets `.enrichment` (and `.alert_display_id` when known) on each IOC
    ORM instance in place (see IOCWithEnrichmentOut / IOCOut)."""
    for ioc in iocs:
        latest = (
            db.query(IOCEnrichment)
            .filter(IOCEnrichment.ioc_id == ioc.id)
            .order_by(IOCEnrichment.enriched_at.desc())
            .first()
        )
        ioc.enrichment = latest  # dynamic attribute; read by IOCWithEnrichmentOut.model_validate
        if alert_display_id:
            ioc.alert_display_id = alert_display_id


@router.get("/{alert_db_id}", response_model=AlertDetailOut)
def get_alert(alert_db_id: str, db: Session = Depends(get_db)) -> Alert:
    alert = db.query(Alert).filter(Alert.id == alert_db_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    _attach_latest_enrichment(db, alert.iocs, alert_display_id=alert.alert_id)
    return alert
