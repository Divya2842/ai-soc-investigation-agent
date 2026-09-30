from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"

    # Primary key
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_uuid,
    )

    # Relationship to IOC
    ioc_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("iocs.id"),
        index=True,
    )

    # Provider information
    provider: Mapped[str] = mapped_column(
        String(32)
    )

    source: Mapped[str] = mapped_column(
        String(32)
    )

    # Enrichment status
    status: Mapped[str] = mapped_column(
        String(16),
        default="completed",
    )

    # Reputation
    reputation: Mapped[str] = mapped_column(
        String(16),
        default="unknown",
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        default=0.0,
    )

    # Reputation statistics
    malicious_count: Mapped[int | None] = mapped_column(
        nullable=True
    )

    suspicious_count: Mapped[int | None] = mapped_column(
        nullable=True
    )

    harmless_count: Mapped[int | None] = mapped_column(
        nullable=True
    )

    # First and last seen
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Threat intelligence
    related_malware: Mapped[list] = mapped_column(
        JSON,
        default=list,
    )

    related_threat_actor: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    # Network information
    asn: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    isp: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    country: Mapped[str | None] = mapped_column(
        String(8),
        nullable=True,
    )

    # Domain information
    created_year: Mapped[int | None] = mapped_column(
        nullable=True,
    )

    owner: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )

    # Hash information
    digitally_signed_by: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )

    # Original provider response
    raw_response: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
    )

    # Enrichment timestamp
    enriched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )