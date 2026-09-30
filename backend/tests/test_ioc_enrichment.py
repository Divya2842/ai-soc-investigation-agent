from app.services.ioc.enrichment.local_mock import LocalMockProvider
from app.services.ioc.enrichment.router import enrich


def test_local_mock_known_malicious_ip():
    provider = LocalMockProvider()
    result = provider.enrich_ip("185.220.101.7")
    assert result.reputation == "malicious"
    assert result.source == "local_mock"
    assert result.confidence > 0.5


def test_local_mock_unknown_ip_returns_unknown():
    provider = LocalMockProvider()
    result = provider.enrich_ip("8.8.4.4")
    assert result.reputation == "unknown"


def test_local_mock_known_malicious_domain():
    provider = LocalMockProvider()
    result = provider.enrich_domain("secure-office365-login.top")
    assert result.reputation == "malicious"


def test_local_mock_hash_classification_by_length():
    provider = LocalMockProvider()
    result = provider.enrich_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert result.ioc_type == "sha256"
    assert result.reputation == "malicious"


def test_local_mock_returns_status_and_counts():
    provider = LocalMockProvider()
    malicious = provider.enrich_ip("185.220.101.7")
    assert malicious.status == "completed"
    assert malicious.malicious_count == 1
    assert malicious.suspicious_count == 0
    assert malicious.harmless_count == 0

    unknown = provider.enrich_ip("8.8.4.4")
    assert unknown.status == "completed"
    assert unknown.malicious_count == 0


def test_router_falls_back_to_local_mock_without_external_keys():
    result = enrich("ipv4", "185.220.101.7")
    assert result.source == "local_mock"
    assert result.reputation == "malicious"


def test_router_email_type_returns_unknown_gracefully():
    result = enrich("email", "someone@example.com")
    assert result.reputation == "unknown"
    assert result.status == "not_available"
