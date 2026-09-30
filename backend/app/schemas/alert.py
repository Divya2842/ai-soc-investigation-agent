from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ioc_enrichment import IOCEnrichmentOut


class AlertCreate(BaseModel):
    """Inbound payload for POST /api/alerts."""

    alert_id: str = Field(..., max_length=64)
    alert_name: str = Field(..., max_length=256)
    severity: str = Field(..., pattern="^(informational|low|medium|high|critical)$")
    timestamp: datetime
    source: str

    user: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    description: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)


class IOCOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str  # internal Alert UUID this IOC was extracted from
    alert_display_id: str | None = None  # human-readable alert_id, e.g. "ALRT-1007" -- for IOC Lookup
    ioc_type: str
    value: str
    first_extracted_at: datetime


class IOCWithEnrichmentOut(IOCOut):
    """
    IOC plus its latest enrichment, if any has completed yet. Used
    everywhere an analyst needs to see reputation without an extra
    round-trip or a manual "Enrich" click -- enrichment is triggered
    automatically in the background as soon as an alert is created (see
    api/alerts.py), so by the time an analyst opens the alert or IOC
    lookup page it's normally already populated.
    """

    enrichment: IOCEnrichmentOut | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    alert_name: str
    severity: str
    timestamp: datetime
    source: str
    user: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    description: str | None = None
    status: str
    created_at: datetime


class AlertDetailOut(AlertOut):
    iocs: list[IOCWithEnrichmentOut] = Field(default_factory=list)


class AlertCreateResponse(BaseModel):
    id: str
    alert_id: str
    status: str
    extracted_iocs: list[IOCOut]


class AlertStatsOut(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    informational: int
    investigated: int
