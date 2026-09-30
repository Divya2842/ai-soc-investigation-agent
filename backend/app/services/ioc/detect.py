"""Deterministic IOC type detection, reused by enrichment routing."""
from __future__ import annotations

from app.services.ioc.extract import (
    _DOMAIN_RE,
    _EMAIL_RE,
    _IPV4_RE,
    _IPV6_RE,
    _MD5_RE,
    _SHA1_RE,
    _SHA256_RE,
    _URL_RE,
)

VALID_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"}


def detect_ioc_type(value: str) -> str | None:
    """Best-effort detection of an IOC's type from its raw value alone."""
    v = value.strip()
    if not v:
        return None
    if _URL_RE.fullmatch(v):
        return "url"
    if _IPV4_RE.fullmatch(v):
        return "ipv4"
    if _IPV6_RE.fullmatch(v) and v.count(":") >= 2:
        return "ipv6"
    if _EMAIL_RE.fullmatch(v):
        return "email"
    if _SHA256_RE.fullmatch(v):
        return "sha256"
    if _SHA1_RE.fullmatch(v):
        return "sha1"
    if _MD5_RE.fullmatch(v):
        return "md5"
    if _DOMAIN_RE.fullmatch(v):
        return "domain"
    return None
