from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import JSON


class IOCEnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    ioc_id: str
    source: str
    status: str
    reputation: str
    confidence: float
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related_malware: list[str] = []
    related_threat_actor: str | None = None
    asn: str | None = None
    isp: str | None = None
    country: str | None = None
    created_year: int | None = None
    owner: str | None = None
    digitally_signed_by: str | None = None
    raw_response: dict[str, Any] = {}
    enriched_at: datetime
