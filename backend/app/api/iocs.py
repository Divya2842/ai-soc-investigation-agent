from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.alert import Alert
from app.models.ioc import IOC
from app.models.ioc_enrichment import IOCEnrichment
from app.schemas.alert import IOCWithEnrichmentOut
from app.schemas.ioc_enrichment import IOCEnrichmentOut
from app.services.ioc.enrichment.service import enrich_and_persist

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


def _latest_enrichment_subquery_map(db: Session, ioc_ids: list[str]) -> dict[str, IOCEnrichment]:
    if not ioc_ids:
        return {}
    rows = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id.in_(ioc_ids))
        .order_by(IOCEnrichment.ioc_id, IOCEnrichment.enriched_at.desc())
        .all()
    )
    latest: dict[str, IOCEnrichment] = {}
    for row in rows:
        if row.ioc_id not in latest:  # first row per ioc_id wins (already sorted desc by enriched_at)
            latest[row.ioc_id] = row
    return latest


@router.get("", response_model=list[IOCWithEnrichmentOut])
def list_iocs(
    response: Response,
    ioc_type: str | None = Query(default=None),
    alert_id: str | None = Query(default=None, description="Internal alert UUID"),
    alert_display_id: str | None = Query(
        default=None, description="Human-readable alert ID, e.g. 'ALRT-1007' (substring match)"
    ),
    reputation: str | None = Query(default=None, description="clean | suspicious | malicious | unknown"),
    q: str | None = Query(default=None, description="Substring match against the IOC value"),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[IOC]:
    """
    Every IOC comes back with its latest enrichment already embedded (see
    IOCWithEnrichmentOut) -- enrichment happens automatically in the
    background as soon as an alert is ingested, so there's no "Enrich"
    button for an analyst to click here. Each IOC also carries the
    human-readable `alert_display_id` of the alert it came from ("Related
    Alert ID" in the IOC Lookup page).
    """
    query = db.query(IOC)
    if ioc_type:
        query = query.filter(IOC.ioc_type == ioc_type)
    if alert_id:
        query = query.filter(IOC.alert_id == alert_id)
    if alert_display_id:
        query = query.join(Alert, Alert.id == IOC.alert_id).filter(
            Alert.alert_id.ilike(f"%{alert_display_id}%")
        )
    if q:
        query = query.filter(IOC.value.ilike(f"%{q}%"))

    all_matching_ids = [row.id for row in query.with_entities(IOC.id).all()]
    enrichment_map = _latest_enrichment_subquery_map(db, all_matching_ids)

    if reputation:
        # Reputation lives on the (separate) enrichment table, so this
        # filter is applied in Python against the already-fetched latest
        # enrichment per IOC rather than a SQL join -- simple and fast at
        # this dataset's scale; revisit with a proper join if the IOC table
        # grows large enough for that to matter.
        matching_ids = {
            ioc_id for ioc_id, enr in enrichment_map.items() if enr.reputation == reputation
        }
        query = query.filter(IOC.id.in_(matching_ids))

    total = query.count()
    response.headers["X-Total-Count"] = str(total)

    iocs = query.order_by(IOC.first_extracted_at.desc()).offset(offset).limit(limit).all()
    if iocs:
        alert_ids = list({ioc.alert_id for ioc in iocs})
        display_ids = {
            a.id: a.alert_id for a in db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
        }
        for ioc in iocs:
            ioc.enrichment = enrichment_map.get(ioc.id)
            ioc.alert_display_id = display_ids.get(ioc.alert_id)
    return iocs


@router.get("/{ioc_id}/enrichment", response_model=IOCEnrichmentOut)
def get_ioc_enrichment(ioc_id: str, db: Session = Depends(get_db)) -> IOCEnrichment:
    """
    Returns cached enrichment (normally already populated automatically in
    the background right after the alert was created). Falls back to
    enriching synchronously here only if that background task hasn't
    completed yet or a row is somehow missing -- this endpoint is a safety
    net, not the primary enrichment path.
    """
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="ioc not found")

    cached = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.ioc_id == ioc_id)
        .order_by(IOCEnrichment.enriched_at.desc())
        .first()
    )
    if cached:
        return cached

    return enrich_and_persist(db, ioc)
