import httpx
import pytest

from app.services.ioc.enrichment.external import AbuseIPDBProvider, VirusTotalProvider


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        return {}


def _patch_client_get(monkeypatch, module, status_code=None, raise_exc=None):
    def fake_get(self, url, **kwargs):
        if raise_exc:
            raise raise_exc
        return _FakeResponse(status_code)

    monkeypatch.setattr(f"{module}.httpx.Client.get", fake_get)


def test_virustotal_timeout_returns_failed_status(monkeypatch):
    _patch_client_get(
        monkeypatch, "app.services.ioc.enrichment.external", raise_exc=httpx.TimeoutException("timeout")
    )
    provider = VirusTotalProvider(api_key="fake-key")
    result = provider.enrich_ip("1.2.3.4")
    assert result.status == "failed"
    assert "timeout" in result.raw_response["error"]


def test_virustotal_invalid_key_returns_failed_status(monkeypatch):
    _patch_client_get(monkeypatch, "app.services.ioc.enrichment.external", status_code=401)
    provider = VirusTotalProvider(api_key="bad-key")
    result = provider.enrich_ip("1.2.3.4")
    assert result.status == "failed"
    assert "invalid_api_key" in result.raw_response["error"]


def test_virustotal_rate_limit_returns_failed_status(monkeypatch):
    _patch_client_get(monkeypatch, "app.services.ioc.enrichment.external", status_code=429)
    provider = VirusTotalProvider(api_key="fake-key")
    result = provider.enrich_domain("example.com")
    assert result.status == "failed"
    assert "rate_limited" in result.raw_response["error"]


def test_abuseipdb_timeout_returns_failed_status(monkeypatch):
    _patch_client_get(
        monkeypatch, "app.services.ioc.enrichment.external", raise_exc=httpx.TimeoutException("timeout")
    )
    provider = AbuseIPDBProvider(api_key="fake-key")
    result = provider.enrich_ip("1.2.3.4")
    assert result.status == "failed"


def test_abuseipdb_unsupported_types_are_not_available():
    provider = AbuseIPDBProvider(api_key="fake-key")
    assert provider.enrich_domain("example.com").status == "not_available"
    assert provider.enrich_url("http://example.com").status == "not_available"
    assert provider.enrich_hash("deadbeef").status == "not_available"


def test_router_falls_back_to_local_mock_when_external_ip_fails(monkeypatch):
    from app.config import settings as settings_module

    monkeypatch.setattr(settings_module.settings, "vt_api_key", "fake-key")
    _patch_client_get(
        monkeypatch, "app.services.ioc.enrichment.external", raise_exc=httpx.TimeoutException("timeout")
    )

    from app.services.ioc.enrichment.router import enrich

    result = enrich("ipv4", "185.220.101.7")
    # VT failed -> must fall back to local mock rather than surfacing a bare failure.
    assert result.source == "local_mock"
    assert result.reputation == "malicious"
