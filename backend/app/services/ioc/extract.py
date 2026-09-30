"""
Deterministic IOC extraction.

Per the project requirements: IOC extraction must NOT rely on the LLM.
Everything here is plain regex/parsing over structured alert fields plus the
raw_event blob and command_line text. Results are normalized and
deduplicated before being handed back to the caller (the API layer persists
them).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# --- Regex patterns -----------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Deliberately conservative full IPv6 pattern (covers the common
# non-abbreviated and "::"-abbreviated forms used in sample data/logs).
_IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b"
)

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|biz|info|ru|cn|xyz|top|club|online|site|link|icu|"
    r"gov|edu|mil|us|uk|de|fr|jp)\b",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Fields on an alert (or raw_event dict) that we specifically pull structured
# values from, in addition to free-text scanning.
_STRUCTURED_FIELDS = (
    "source_ip",
    "destination_ip",
    "domain",
    "url",
    "file_hash",
)


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | email
    value: str


def _normalize(value: str) -> str:
    return value.strip().strip(").,;:'\"").lower()


def _classify_hash(value: str) -> str | None:
    length = len(value)
    if length == 64:
        return "sha256"
    if length == 40:
        return "sha1"
    if length == 32:
        return "md5"
    return None


def _flatten_text(raw_event: dict[str, Any] | None) -> str:
    """Turn a raw_event dict into a single text blob to scan for IOCs."""
    if not raw_event:
        return ""
    try:
        return json.dumps(raw_event, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(raw_event)


def extract_iocs(
    *,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    domain: str | None = None,
    url: str | None = None,
    file_hash: str | None = None,
    command_line: str | None = None,
    description: str | None = None,
    raw_event: dict[str, Any] | None = None,
) -> list[ExtractedIOC]:
    """
    Extract, normalize, and deduplicate IOCs from an alert's structured
    fields plus free text (command_line, description, raw_event).

    Structured fields are trusted more directly (e.g. `file_hash` is
    classified by length rather than re-discovered by regex), but every
    value is still normalized and validated before being returned.
    """
    found: dict[tuple[str, str], ExtractedIOC] = {}

    def _add(ioc_type: str, raw_value: str) -> None:
        value = _normalize(raw_value)
        if not value:
            return
        key = (ioc_type, value)
        found.setdefault(key, ExtractedIOC(ioc_type=ioc_type, value=value))

    # 1. Structured fields first (highest confidence, avoids false negatives
    #    when the value doesn't happen to match a regex edge case).
    if source_ip and _IPV4_RE.fullmatch(source_ip.strip()):
        _add("ipv4", source_ip)
    elif source_ip and _IPV6_RE.fullmatch(source_ip.strip()):
        _add("ipv6", source_ip)

    if destination_ip and _IPV4_RE.fullmatch(destination_ip.strip()):
        _add("ipv4", destination_ip)
    elif destination_ip and _IPV6_RE.fullmatch(destination_ip.strip()):
        _add("ipv6", destination_ip)

    if domain:
        _add("domain", domain)

    if url:
        _add("url", url)

    if file_hash:
        hash_type = _classify_hash(file_hash.strip())
        if hash_type:
            _add(hash_type, file_hash)

    # 2. Free-text scanning (command_line, description, raw_event) — this is
    #    where most real-world IOCs get missed if you only trust structured
    #    fields, e.g. an IP embedded in a PowerShell command line.
    blob = " ".join(
        part
        for part in (command_line, description, _flatten_text(raw_event))
        if part
    )

    if blob:
        for match in _URL_RE.findall(blob):
            _add("url", match)
        for match in _IPV4_RE.findall(blob):
            _add("ipv4", match)
        for match in _IPV6_RE.findall(blob):
            # Avoid classifying a bare "::" fragment from timestamps etc.
            if match.count(":") >= 2:
                _add("ipv6", match)
        for match in _EMAIL_RE.findall(blob):
            _add("email", match)
        for match in _SHA256_RE.findall(blob):
            _add("sha256", match)
        for match in _SHA1_RE.findall(blob):
            # SHA1 pattern also matches inside longer hex strings already
            # captured as SHA256; skip if it's a substring of one already found.
            if not any(match in v.value for (t, _), v in found.items() if t == "sha256"):
                _add("sha1", match)
        for match in _MD5_RE.findall(blob):
            if not any(
                match in v.value for (t, _), v in found.items() if t in ("sha256", "sha1")
            ):
                _add("md5", match)
        for match in _DOMAIN_RE.findall(blob):
            # Skip domain-looking substrings that are actually part of a URL
            # or an email address already captured.
            if any(match in v.value for (t, _), v in found.items() if t in ("url", "email")):
                continue
            _add("domain", match)

    return list(found.values())
