def _powershell_alert(alert_id="ALRT-INT-1"):
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
        "command_line": "powershell.exe -enc SQBFAFgA hidden window",
        "url": "http://185.220.101.7/p.ps1",
        "description": "Encoded PowerShell download cradle spawned from WINWORD.EXE",
        "raw_event": {"parent_process": "WINWORD.EXE"},
    }


def test_full_investigation_pipeline(client):
    # 1. Ingest alert (triggers deterministic IOC extraction + automatic
    #    background enrichment)
    create_resp = client.post("/api/alerts", json=_powershell_alert())
    assert create_resp.status_code == 201
    alert_db_id = create_resp.json()["id"]
    assert len(create_resp.json()["extracted_iocs"]) >= 2

    # 2. Run the agent (enrichment -> log correlation -> MITRE -> risk -> AI/deterministic summary)
    investigate_resp = client.post(f"/api/alerts/{alert_db_id}/investigate")
    assert investigate_resp.status_code == 201
    investigation = investigate_resp.json()

    # Deterministic layers must have produced real content (no GROQ_API_KEY
    # set in tests, so this exercises the deterministic fallback summary).
    assert investigation["llm_used"] is False
    assert investigation["status"] == "completed"
    assert investigation["severity"] in ("low", "medium", "high", "critical")
    assert isinstance(investigation["risk_score"], (int, float))
    assert any(t["technique_id"] == "T1059.001" for t in investigation["attack_techniques"])
    assert investigation["recommended_actions"]
    assert investigation["disposition"] in (
        "true_positive", "false_positive", "benign_positive", "suspicious", "inconclusive",
    )
    assert "rag_sources" not in investigation  # internal retrieval metadata must never reach the API

    # Alert status must reflect a *completed* investigation, not stay stuck
    # on "investigating".
    alert_resp = client.get(f"/api/alerts/{alert_db_id}")
    assert alert_resp.json()["status"] == "investigated"

    # 3. Fetch the investigation back
    get_resp = client.get(f"/api/investigations/{investigation['id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == investigation["id"]

    # 3b. Analyst report: structured, evidence-based, no RAG/source leakage
    report_resp = client.get(f"/api/investigations/{investigation['id']}/report")
    assert report_resp.status_code == 200
    report = report_resp.json()["report_markdown"]
    assert "# Incident Summary" in report
    assert "## 1. Entity Details" in report
    assert "## 5. Conclusion" in report
    assert "T1059.001" in report
    for leaked_term in ("knowledge_base", "playbook.md", "rag_sources", "vector"):
        assert leaked_term not in report.lower()

    # 3c. Customer escalation format is available on request, in the
    # required structure, without being forced.
    customer_resp = client.get(
        f"/api/investigations/{investigation['id']}/report", params={"format": "customer"}
    )
    assert customer_resp.status_code == 200
    customer_report = customer_resp.json()["report_markdown"]
    assert customer_report.startswith("Hi Team,")
    assert "Disposition:" in customer_report
    assert "Customer Action Items:" in customer_report

    # 4. Response actions were created and can be approved (simulated only)
    list_resp = client.get(f"/api/response/{investigation['id']}")
    assert list_resp.status_code == 200
    actions = list_resp.json()
    assert len(actions) >= 1
    assert all(a["status"] == "recommended" for a in actions)

    approve_resp = client.post(
        f"/api/response/{investigation['id']}/approve", json={"approved_by": "test-analyst"}
    )
    assert approve_resp.status_code == 200
    approved = approve_resp.json()
    assert all(a["status"] == "simulated_executed" for a in approved)
    assert all("[SIMULATED]" in a["simulated_result"] for a in approved)


def test_investigated_count_updates_after_investigation(client):
    create_resp = client.post("/api/alerts", json=_powershell_alert("ALRT-STATS-INV"))
    alert_db_id = create_resp.json()["id"]

    before = client.get("/api/alerts/stats").json()
    assert before["investigated"] == 0

    client.post(f"/api/alerts/{alert_db_id}/investigate")

    after = client.get("/api/alerts/stats").json()
    assert after["investigated"] == 1


def test_investigation_of_unknown_alert_404s(client):
    resp = client.post("/api/alerts/does-not-exist/investigate")
    assert resp.status_code == 404


def test_atlas_not_forced_on_traditional_alert(client):
    create_resp = client.post("/api/alerts", json=_powershell_alert("ALRT-INT-ATLAS"))
    alert_db_id = create_resp.json()["id"]
    investigate_resp = client.post(f"/api/alerts/{alert_db_id}/investigate")
    body = investigate_resp.json()
    # A normal PowerShell alert has no AI/ML signal -- ATLAS must be empty.
    assert body["atlas_techniques"] == []

    report_resp = client.get(f"/api/investigations/{body['id']}/report")
    report = report_resp.json()["report_markdown"]
    assert "No ATLAS mapping identified from the collected evidence." in report
