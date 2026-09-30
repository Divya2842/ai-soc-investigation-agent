"""
Bridges the pure `enrich()` router function to database persistence.

The router is responsible only for selecting and calling an enrichment
provider. This service persists the returned EnrichmentResult.

No LocalMock provider is used here.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.ioc import IOC
from app.models.ioc_enrichment import IOCEnrichment
from app.services.ioc.enrichment.router import enrich

logger = logging.getLogger(__name__)


def enrich_and_persist(
    db: Session,
    ioc: IOC,
) -> IOCEnrichment:
    """
    Enrich one IOC and persist the result.

    If the provider unexpectedly raises an exception, persist a failed
    external-enrichment result instead of allowing the exception to break
    alert ingestion.
    """

    try:
        result = enrich(
            ioc.ioc_type,
            ioc.value,
        )

    except Exception as exc:  # noqa: BLE001
        logger.exception(
            "Unexpected error enriching IOC %s (%s)",
            ioc.value,
            ioc.ioc_type,
        )

        row = IOCEnrichment(
            ioc_id=ioc.id,
            provider="external",
            source="external",
            status="failed",
            reputation="unknown",
            confidence=0.0,
            raw_response={
                "error": f"unexpected_enrichment_error: {exc}"[:500]
            },
        )

        db.add(row)
        db.commit()
        db.refresh(row)

        return row

    row = IOCEnrichment(
        ioc_id=ioc.id,
        provider=result.source,
        source=result.source,
        status=result.status,
        reputation=result.reputation,
        confidence=result.confidence,
        malicious_count=result.malicious_count,
        suspicious_count=result.suspicious_count,
        harmless_count=result.harmless_count,
        first_seen=result.first_seen,
        last_seen=result.last_seen,
        related_malware=result.related_malware,
        related_threat_actor=result.related_threat_actor,
        asn=result.asn,
        isp=result.isp,
        country=result.country,
        created_year=result.created_year,
        owner=result.owner,
        digitally_signed_by=result.digitally_signed_by,
        raw_response=result.raw_response,
    )

    db.add(row)
    db.commit()
    db.refresh(row)

    return row


def enrich_alert_iocs_background(
    db_factory,
    alert_id: str,
    ioc_ids: list[str],
) -> None:
    """
    Background-task entry point.

    Creates a fresh database session, enriches the requested IOCs,
    and always closes the session.
    """

    db = db_factory()

    try:
        iocs = (
            db.query(IOC)
            .filter(IOC.id.in_(ioc_ids))
            .all()
        )

        for ioc in iocs:
            enrich_and_persist(
                db,
                ioc,
            )

    finally:
        db.close()