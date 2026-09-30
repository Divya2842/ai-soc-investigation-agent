"""
Routes an IOC to the configured external threat-intelligence providers.

Provider priority:

1. VirusTotal
2. AbuseIPDB for IP addresses

There is NO LocalMockProvider fallback.

Private/internal IP addresses are identified locally using Python's
ipaddress module because public threat-intelligence reputation is not
applicable to RFC1918/internal addresses.
"""

from __future__ import annotations

import ipaddress

from app.config.settings import settings
from app.services.ioc.enrichment.base import (
    EnrichmentProvider,
    EnrichmentResult,
)


# =========================================================
# EXTERNAL PROVIDERS
# =========================================================

def _external_providers() -> list[EnrichmentProvider]:
    """
    Return configured external enrichment providers.

    VirusTotal is preferred when its API key is configured.

    AbuseIPDB is also loaded when configured and is useful primarily
    for public IP reputation.
    """

    providers: list[EnrichmentProvider] = []

    # -----------------------------------------------------
    # VirusTotal
    # -----------------------------------------------------

    if settings.vt_api_key:

        from app.services.ioc.enrichment.external import (
            VirusTotalProvider,
        )

        providers.append(
            VirusTotalProvider(
                settings.vt_api_key
            )
        )

    # -----------------------------------------------------
    # AbuseIPDB
    # -----------------------------------------------------

    if settings.abuseipdb_api_key:

        from app.services.ioc.enrichment.external import (
            AbuseIPDBProvider,
        )

        providers.append(
            AbuseIPDBProvider(
                settings.abuseipdb_api_key
            )
        )

    return providers


# =========================================================
# PRIVATE IP DETECTION
# =========================================================

def _is_private_ip(value: str) -> bool:
    """
    Determine whether an IP address is private/internal.

    Examples:

        10.10.5.9       -> True
        192.168.1.10    -> True
        172.16.10.20    -> True
        8.8.8.8         -> False
        45.142.212.61   -> False
    """

    try:

        ip = ipaddress.ip_address(
            value.strip()
        )

        return ip.is_private

    except ValueError:

        return False


# =========================================================
# PRIVATE IP RESULT
# =========================================================

def _private_ip_result(
    value: str,
) -> EnrichmentResult:
    """
    Return a deterministic classification for a private IP.

    This is NOT LocalMock threat intelligence.

    It simply identifies the address as private/internal using the
    standard Python IP address library.
    """

    ioc_type = (
        "ipv6"
        if ":" in value
        else "ipv4"
    )

    return EnrichmentResult(
        ioc_value=value,
        ioc_type=ioc_type,

        source="system",

        status="completed",

        reputation="private",

        confidence=1.0,

        malicious_count=0,
        suspicious_count=0,
        harmless_count=0,

        first_seen=None,
        last_seen=None,

        related_malware=[],
        related_threat_actor=None,

        asn=None,
        isp=None,
        country=None,

        created_year=None,
        owner=None,
        digitally_signed_by=None,

        raw_response={
            "classification": "private_ip",
            "note": (
                "Private/internal IP address. "
                "Public threat-intelligence reputation "
                "is not applicable."
            ),
        },
    )


# =========================================================
# NO PROVIDER RESULT
# =========================================================

def _not_available_result(
    ioc_type: str,
    value: str,
    reason: str,
) -> EnrichmentResult:
    """
    Return a safe result when no external provider can enrich
    the IOC.

    There is deliberately no LocalMock fallback.
    """

    return EnrichmentResult(
        ioc_value=value,
        ioc_type=ioc_type,

        source="external",

        status="not_available",

        reputation="unknown",

        confidence=0.0,

        malicious_count=None,
        suspicious_count=None,
        harmless_count=None,

        first_seen=None,
        last_seen=None,

        related_malware=[],
        related_threat_actor=None,

        asn=None,
        isp=None,
        country=None,

        created_year=None,
        owner=None,
        digitally_signed_by=None,

        raw_response={
            "note": reason,
        },
    )


# =========================================================
# IOC ENRICHMENT ROUTER
# =========================================================

def enrich(
    ioc_type: str,
    value: str,
) -> EnrichmentResult:
    """
    Enrich an IOC using external threat-intelligence providers.

    Supported:

        ipv4
        ipv6
        domain
        url
        md5
        sha1
        sha256
        email

    There is no LocalMock fallback.
    """

    ioc_type = (
        str(ioc_type)
        .strip()
        .lower()
    )

    value = (
        str(value)
        .strip()
    )

    # =====================================================
    # PRIVATE IP
    # =====================================================

    if ioc_type in (
        "ipv4",
        "ipv6",
    ):

        if _is_private_ip(value):

            return _private_ip_result(
                value
            )

    # =====================================================
    # LOAD EXTERNAL PROVIDERS
    # =====================================================

    providers = _external_providers()

    # =====================================================
    # NO EXTERNAL PROVIDER CONFIGURED
    # =====================================================

    if not providers:

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "No external IOC enrichment provider "
                "is configured."
            ),
        )

    # =====================================================
    # IP ADDRESS
    # =====================================================

    if ioc_type in (
        "ipv4",
        "ipv6",
    ):

        for provider in providers:

            result = provider.enrich_ip(
                value
            )

            if result.status == "completed":

                return result

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "External providers were configured, "
                "but none returned a completed enrichment result."
            ),
        )

    # =====================================================
    # DOMAIN
    # =====================================================

    if ioc_type == "domain":

        for provider in providers:

            result = provider.enrich_domain(
                value
            )

            if result.status == "completed":

                return result

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "No configured external provider "
                "returned domain enrichment."
            ),
        )

    # =====================================================
    # URL
    # =====================================================

    if ioc_type == "url":

        for provider in providers:

            result = provider.enrich_url(
                value
            )

            if result.status == "completed":

                return result

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "No configured external provider "
                "returned URL enrichment."
            ),
        )

    # =====================================================
    # HASH
    # =====================================================

    if ioc_type in (
        "md5",
        "sha1",
        "sha256",
    ):

        for provider in providers:

            result = provider.enrich_hash(
                value
            )

            if result.status == "completed":

                return result

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "No configured external provider "
                "returned hash enrichment."
            ),
        )

    # =====================================================
    # EMAIL
    # =====================================================

    if ioc_type == "email":

        return _not_available_result(
            ioc_type=ioc_type,
            value=value,
            reason=(
                "Email reputation enrichment is not "
                "implemented by the configured external "
                "providers."
            ),
        )

    # =====================================================
    # UNSUPPORTED IOC TYPE
    # =====================================================

    return _not_available_result(
        ioc_type=ioc_type,
        value=value,
        reason=(
            f"No external enrichment provider supports "
            f"IOC type '{ioc_type}'."
        ),
    )