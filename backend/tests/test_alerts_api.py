def _sample_payload(alert_id="ALRT-TEST-1"):
    return {
        "alert_id": alert_id,
        "alert_name": "Suspicious PowerShell Execution",
        "severity": "high",
        "timestamp": "2026-09-08T14:22:11Z",
        "source": "EDR",
        "user": "j.martinez",
        "hostname": "WKS-0231",
        "source_ip": "10.10.12.45",
        "destination_ip": "185.220.101.7",
        "command_line": "powershell.exe -enc SQBFAFgA",
        "url": "http://185.220.101.7/p.ps1",
        "description": "Encoded PowerShell download cradle",
        "raw_event": {"sha256": "9f4c1a2b7e8d5f3a6c0b1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a"},
    }


def test_create_alert_extracts_iocs(client):
    resp = client.post("/api/alerts", json=_sample_payload())
    assert resp.status_code == 201
    body = resp.json()
    assert body["alert_id"] == "ALRT-TEST-1"
    assert body["status"] == "new"
    ioc_types = {i["ioc_type"] for i in body["extracted_iocs"]}
    assert "ipv4" in ioc_types
    assert "url" in ioc_types
    assert "sha256" in ioc_types


def test_duplicate_alert_id_rejected(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-DUP"))
    resp = client.post("/api/alerts", json=_sample_payload("ALRT-DUP"))
    assert resp.status_code == 409


def test_list_alerts(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-LIST-1"))
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_get_alert_detail_includes_iocs(client):
    create_resp = client.post("/api/alerts", json=_sample_payload("ALRT-DETAIL-1"))
    alert_id = create_resp.json()["id"]
    resp = client.get(f"/api/alerts/{alert_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_id"] == "ALRT-DETAIL-1"
    assert len(body["iocs"]) >= 3


def test_ioc_enrichment_happens_automatically_without_manual_trigger(client):
    """
    Per the automatic-enrichment requirement: an analyst should never need
    to click an "Enrich" button. Enrichment runs as a background task
    triggered by alert creation -- by the time the alert-detail response
    comes back, every extracted IOC should already have enrichment data
    embedded, with no separate call to /api/iocs/{id}/enrichment.
    """
    create_resp = client.post("/api/alerts", json=_sample_payload("ALRT-AUTO-ENRICH"))
    alert_id = create_resp.json()["id"]
    resp = client.get(f"/api/alerts/{alert_id}")
    body = resp.json()
    assert len(body["iocs"]) >= 3
    for ioc in body["iocs"]:
        assert ioc["enrichment"] is not None
        assert ioc["enrichment"]["status"] in ("completed", "failed", "not_available")
        assert "reputation" in ioc["enrichment"]
        assert ioc["alert_display_id"] == "ALRT-AUTO-ENRICH"  # "Related Alert ID"
    # The known-malicious IP in the sample payload must actually resolve malicious.
    malicious_ip = next(i for i in body["iocs"] if i["value"] == "185.220.101.7")
    assert malicious_ip["enrichment"]["reputation"] == "malicious"
    assert malicious_ip["enrichment"]["malicious_count"] is not None


def test_get_nonexistent_alert_404(client):
    resp = client.get("/api/alerts/does-not-exist")
    assert resp.status_code == 404


def test_list_iocs_filter_by_type(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-IOC-FILTER"))
    resp = client.get("/api/iocs", params={"ioc_type": "sha256"})
    assert resp.status_code == 200
    for ioc in resp.json():
        assert ioc["ioc_type"] == "sha256"


def test_list_iocs_embeds_enrichment(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-IOC-ENRICH-LIST"))
    resp = client.get("/api/iocs")
    assert resp.status_code == 200
    body = resp.json()
    assert any(ioc["enrichment"] is not None for ioc in body)
    assert any(ioc["alert_display_id"] == "ALRT-IOC-ENRICH-LIST" for ioc in body)


def test_list_iocs_filter_by_alert_display_id(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-DISPLAY-FILTER"))
    resp = client.get("/api/iocs", params={"alert_display_id": "ALRT-DISPLAY-FILTER"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) >= 1
    assert all(ioc["alert_display_id"] == "ALRT-DISPLAY-FILTER" for ioc in body)


def test_list_iocs_filter_by_reputation(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-IOC-REP-FILTER"))
    resp = client.get("/api/iocs", params={"reputation": "malicious"})
    assert resp.status_code == 200
    for ioc in resp.json():
        assert ioc["enrichment"]["reputation"] == "malicious"


def test_alerts_search_matches_hostname(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-SEARCH-1"))
    resp = client.get("/api/alerts", params={"search": "WKS-0231"})
    assert resp.status_code == 200
    assert any(a["alert_id"] == "ALRT-SEARCH-1" for a in resp.json())


def test_alerts_search_no_match_returns_empty(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-SEARCH-2"))
    resp = client.get("/api/alerts", params={"search": "no-such-host-xyz"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_alerts_list_returns_total_count_header(client):
    client.post("/api/alerts", json=_sample_payload("ALRT-PAGE-1"))
    client.post("/api/alerts", json=_sample_payload("ALRT-PAGE-2"))
    resp = client.get("/api/alerts", params={"limit": 1})
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert int(resp.headers["X-Total-Count"]) >= 2


def test_alert_stats_endpoint_is_dynamic(client):
    resp = client.get("/api/alerts/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "total": 0, "critical": 0, "high": 0, "medium": 0,
        "low": 0, "informational": 0, "investigated": 0,
    }

    client.post("/api/alerts", json=_sample_payload("ALRT-STATS-1"))
    resp2 = client.get("/api/alerts/stats")
    body2 = resp2.json()
    assert body2["total"] == 1
    assert body2["high"] == 1
    assert body2["investigated"] == 0  # not investigated yet


def test_informational_severity_accepted(client):
    payload = _sample_payload("ALRT-INFO-1")
    payload["severity"] = "informational"
    resp = client.post("/api/alerts", json=payload)
    assert resp.status_code == 201


def test_alerts_filter_by_date_range(client):
    payload = _sample_payload("ALRT-DATE-1")
    payload["timestamp"] = "2026-01-01T00:00:00Z"
    client.post("/api/alerts", json=payload)

    # Alert is outside this range -> excluded.
    resp = client.get(
        "/api/alerts", params={"start_date": "2027-01-01T00:00:00Z", "end_date": "2027-12-31T00:00:00Z"}
    )
    assert not any(a["alert_id"] == "ALRT-DATE-1" for a in resp.json())

    # Alert is inside this range -> included.
    resp2 = client.get(
        "/api/alerts", params={"start_date": "2025-12-01T00:00:00Z", "end_date": "2026-02-01T00:00:00Z"}
    )
    assert any(a["alert_id"] == "ALRT-DATE-1" for a in resp2.json())


def test_health_endpoint_reports_groq_status(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "groq_configured" in body
    assert body["status"] == "ok"
