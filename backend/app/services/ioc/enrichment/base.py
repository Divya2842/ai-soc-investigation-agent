from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    """Normalized enrichment result, regardless of which provider produced it."""

    ioc_value: str
    ioc_type: str
    source: str  # "virustotal" | "abuseipdb" | "system" | "external"
    status: str = "completed"  # "pending" | "completed" | "failed" | "not_available"
    reputation: str = "unknown"  # clean | suspicious | malicious | unknown
    confidence: float = 0.0  # 0.0 - 1.0
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    related_malware: list[str] = Field(default_factory=list)
    related_threat_actor: str | None = None
    asn: str | None = None
    isp: str | None = None
    country: str | None = None
    created_year: int | None = None
    owner: str | None = None
    digitally_signed_by: str | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)


class EnrichmentProvider(ABC):
    """
    Interface every enrichment provider must implement. Adding a new
    threat-intel source means writing one adapter class and registering it
    in `router.py` — the agent and API never need to change.
    """

    name: str = "base"

    @abstractmethod
    def enrich_ip(self, value: str) -> EnrichmentResult: ...

    @abstractmethod
    def enrich_domain(self, value: str) -> EnrichmentResult: ...

    @abstractmethod
    def enrich_url(self, value: str) -> EnrichmentResult: ...

    @abstractmethod
    def enrich_hash(self, value: str) -> EnrichmentResult: ...
