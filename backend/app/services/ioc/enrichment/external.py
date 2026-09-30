"""
Optional external threat-intelligence provider adapters.

These are only instantiated (and only ever called) when the corresponding
API key is present in settings. The application does not require a paid API
to function.

Each adapter implements the same `EnrichmentProvider` interface as the
`LocalMockProvider`.

Network calls are intentionally minimal and defensive: any request failure
degrades to an "unknown" result rather than raising, since enrichment
failures must never take down an investigation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.services.ioc.enrichment.base import (
    EnrichmentProvider,
    EnrichmentResult,
)


class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self._api_key = api_key
        self._headers = {"x-apikey": api_key}

    def _get(self, path: str) -> dict:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(
                f"{self.BASE_URL}{path}",
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()

    def _failed_result(
        self,
        ioc_value: str,
        ioc_type: str,
        reason: str,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            status="failed",
            reputation="unknown",
            confidence=0.0,
            raw_response={"error": reason},
        )

    def _safe(
        self,
        path: str,
        ioc_value: str,
        ioc_type: str,
    ) -> EnrichmentResult:

        # ---------------------------------------------------------
        # Call VirusTotal
        # ---------------------------------------------------------
        try:
            data = self._get(path)

        except httpx.TimeoutException:
            return self._failed_result(
                ioc_value,
                ioc_type,
                "virustotal_timeout",
            )

        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code

            if status_code == 401:
                reason = "virustotal_invalid_api_key"
            elif status_code == 429:
                reason = "virustotal_rate_limited"
            elif status_code == 404:
                reason = "virustotal_ioc_not_found"
            else:
                reason = f"virustotal_http_error_{status_code}"

            return self._failed_result(
                ioc_value,
                ioc_type,
                reason,
            )

        except (httpx.HTTPError, ValueError):
            return self._failed_result(
                ioc_value,
                ioc_type,
                "virustotal_lookup_failed",
            )

        # ---------------------------------------------------------
        # Get VirusTotal attributes
        # ---------------------------------------------------------
        attrs = data.get("data", {}).get("attributes", {})

        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total = sum(stats.values()) or 1

        # ---------------------------------------------------------
        # Reputation
        # ---------------------------------------------------------
        if malicious > 0:
            reputation = "malicious"

        elif suspicious > 0:
            reputation = "suspicious"

        else:
            reputation = "clean"

        confidence = min(
            1.0,
            (malicious + suspicious) / total + 0.2,
        )

        # ---------------------------------------------------------
        # IOC-specific fields
        # ---------------------------------------------------------
        country = None
        isp = None
        created_year = None
        owner = None
        digitally_signed_by = None

        # ---------------------------------------------------------
        # IP enrichment
        # ---------------------------------------------------------
        if ioc_type in ("ipv4", "ipv6"):

            country = attrs.get("country")

            # VirusTotal provides the network/ASN owner through
            # the as_owner field.
            isp = attrs.get("as_owner")

        # ---------------------------------------------------------
        # Domain enrichment
        # ---------------------------------------------------------
        elif ioc_type == "domain":

            creation_date = attrs.get("creation_date")

            if creation_date:
                try:
                    created_year = datetime.fromtimestamp(
                        creation_date,
                        tz=timezone.utc,
                    ).year

                except (TypeError, ValueError, OSError):
                    created_year = None

            # Use an actual registrant field if available.
            owner = (
                attrs.get("registrant")
                or attrs.get("registrant_name")
            )

        # ---------------------------------------------------------
        # Hash / file enrichment
        # ---------------------------------------------------------
        elif ioc_type in ("md5", "sha1", "sha256"):

            signature_info = attrs.get("signature_info") or {}

            digitally_signed_by = (
                signature_info.get("publisher")
                or signature_info.get("signer")
                or signature_info.get("company")
            )

        # ---------------------------------------------------------
        # Related malware / threat classification
        # ---------------------------------------------------------
        related_malware = []

        threat_classification = attrs.get(
            "popular_threat_classification"
        )

        if threat_classification:

            suggested_label = threat_classification.get(
                "suggested_threat_label",
                "",
            )

            if suggested_label:
                related_malware = suggested_label.split("/")

        # ---------------------------------------------------------
        # Final enrichment result
        # ---------------------------------------------------------
        return EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            source=self.name,
            status="completed",
            reputation=reputation,
            confidence=round(confidence, 2),

            country=country,
            isp=isp,

            created_year=created_year,
            owner=owner,

            digitally_signed_by=(
                digitally_signed_by
            ),

            related_malware=related_malware,

            raw_response=attrs,
        )

    # =============================================================
    # VirusTotal IOC methods
    # =============================================================

    def enrich_ip(self, value: str) -> EnrichmentResult:
        return self._safe(
            f"/ip_addresses/{value}",
            value,
            "ipv4",
        )

    def enrich_domain(self, value: str) -> EnrichmentResult:
        return self._safe(
            f"/domains/{value}",
            value,
            "domain",
        )

    def enrich_url(self, value: str) -> EnrichmentResult:
        import base64

        url_id = (
            base64.urlsafe_b64encode(value.encode())
            .decode()
            .strip("=")
        )

        return self._safe(
            f"/urls/{url_id}",
            value,
            "url",
        )

    def enrich_hash(self, value: str) -> EnrichmentResult:
        return self._safe(
            f"/files/{value}",
            value,
            "sha256",
        )


class AbuseIPDBProvider(EnrichmentProvider):
    """
    Only meaningfully implements enrich_ip.
    Other methods degrade gracefully.
    """

    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self._api_key = api_key

        self._headers = {
            "Key": api_key,
            "Accept": "application/json",
        }

    def enrich_ip(self, value: str) -> EnrichmentResult:

        try:
            with httpx.Client(timeout=5.0) as client:

                resp = client.get(
                    f"{self.BASE_URL}/check",
                    headers=self._headers,
                    params={
                        "ipAddress": value,
                        "maxAgeInDays": 90,
                    },
                )

                resp.raise_for_status()

                data = resp.json().get(
                    "data",
                    {},
                )

        except httpx.TimeoutException:

            return EnrichmentResult(
                ioc_value=value,
                ioc_type="ipv4",
                source=self.name,
                status="failed",
                reputation="unknown",
                confidence=0.0,
                raw_response={
                    "error": "abuseipdb_timeout"
                },
            )

        except httpx.HTTPStatusError as exc:

            status_code = exc.response.status_code

            reason = {
                401: "abuseipdb_invalid_api_key",
                403: "abuseipdb_invalid_api_key",
                429: "abuseipdb_rate_limited",
            }.get(
                status_code,
                f"abuseipdb_http_error_{status_code}",
            )

            return EnrichmentResult(
                ioc_value=value,
                ioc_type="ipv4",
                source=self.name,
                status="failed",
                reputation="unknown",
                confidence=0.0,
                raw_response={
                    "error": reason
                },
            )

        except (httpx.HTTPError, ValueError):

            return EnrichmentResult(
                ioc_value=value,
                ioc_type="ipv4",
                source=self.name,
                status="failed",
                reputation="unknown",
                confidence=0.0,
                raw_response={
                    "error": "abuseipdb_lookup_failed"
                },
            )

        # ---------------------------------------------------------
        # AbuseIPDB reputation
        # ---------------------------------------------------------
        score = data.get(
            "abuseConfidenceScore",
            0,
        )

        if score >= 75:
            reputation = "malicious"

        elif score >= 25:
            reputation = "suspicious"

        else:
            reputation = "clean"

        # ---------------------------------------------------------
        # Return IP enrichment
        # ---------------------------------------------------------
        return EnrichmentResult(
            ioc_value=value,
            ioc_type="ipv4",
            source=self.name,
            status="completed",
            reputation=reputation,
            confidence=round(score / 100, 2),
            country=data.get("countryCode"),
            isp=data.get("isp"),
            raw_response=data,
        )

    def enrich_domain(
        self,
        value: str,
    ) -> EnrichmentResult:

        return EnrichmentResult(
            ioc_value=value,
            ioc_type="domain",
            source=self.name,
            status="not_available",
            reputation="unknown",
            confidence=0.0,
            raw_response={
                "note": (
                    "AbuseIPDB does not support "
                    "domain lookups"
                )
            },
        )

    def enrich_url(
        self,
        value: str,
    ) -> EnrichmentResult:

        return EnrichmentResult(
            ioc_value=value,
            ioc_type="url",
            source=self.name,
            status="not_available",
            reputation="unknown",
            confidence=0.0,
            raw_response={
                "note": (
                    "AbuseIPDB does not support "
                    "URL lookups"
                )
            },
        )

    def enrich_hash(
        self,
        value: str,
    ) -> EnrichmentResult:

        return EnrichmentResult(
            ioc_value=value,
            ioc_type="sha256",
            source=self.name,
            status="not_available",
            reputation="unknown",
            confidence=0.0,
            raw_response={
                "note": (
                    "AbuseIPDB does not support "
                    "hash lookups"
                )
            },
        )