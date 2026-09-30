from app.services.ioc.extract import extract_iocs


def test_extracts_ipv4_from_structured_field():
    result = extract_iocs(source_ip="10.10.12.45", destination_ip="185.220.101.7")
    values = {(i.ioc_type, i.value) for i in result}
    assert ("ipv4", "10.10.12.45") in values
    assert ("ipv4", "185.220.101.7") in values


def test_extracts_url_and_domain_from_free_text():
    result = extract_iocs(
        description="User connected to http://185.220.101.7/p.ps1 and update-cdn-secure.xyz"
    )
    types = {i.ioc_type for i in result}
    assert "url" in types
    assert "domain" in types


def test_extracts_sha256_and_not_double_counted_as_md5_or_sha1():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = extract_iocs(file_hash=sha256)
    hash_matches = [i for i in result if i.value == sha256]
    assert len(hash_matches) == 1
    assert hash_matches[0].ioc_type == "sha256"


def test_classifies_hash_by_length_md5():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    result = extract_iocs(file_hash=md5)
    assert any(i.ioc_type == "md5" and i.value == md5 for i in result)


def test_extracts_email_address():
    result = extract_iocs(description="Phishing sent from it-support@0ffice365-notify.com")
    assert any(i.ioc_type == "email" for i in result)


def test_deduplicates_repeated_ioc_across_fields():
    result = extract_iocs(
        source_ip="185.220.101.7",
        description="beaconing to 185.220.101.7 observed",
    )
    ip_matches = [i for i in result if i.ioc_type == "ipv4" and i.value == "185.220.101.7"]
    assert len(ip_matches) == 1


def test_normalizes_case_and_trailing_punctuation():
    result = extract_iocs(description="Reached out to EVIL-DOMAIN.COM.")
    assert any(i.ioc_type == "domain" and i.value == "evil-domain.com" for i in result)


def test_extracts_from_raw_event_json_blob():
    result = extract_iocs(
        raw_event={"sha256": "9f4c1a2b7e8d5f3a6c0b1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a"}
    )
    assert any(i.ioc_type == "sha256" for i in result)


def test_empty_input_returns_empty_list():
    assert extract_iocs() == []


def test_ipv6_extraction():
    result = extract_iocs(description="Connection from 2001:db8:85a3::8a2e:370:7334 observed")
    assert any(i.ioc_type == "ipv6" for i in result)
