"""
Lightweight prompt-injection screening.

This is a defense-in-depth heuristic, not a guarantee. It flags
instruction-like content found inside data that will be interpolated into
an LLM prompt (alert descriptions, command lines, log payloads) so it can
be (a) neutralized before being sent, and (b) recorded in the audit log.
It does NOT silently strip content without a trace -- security analysts
need to know when this fired.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_SUSPICIOUS_PATTERNS = [
    r"ignore (all|any|the)? ?previous instructions",
    r"disregard (all|any|the)? ?(prior|previous) instructions",
    r"you are now",
    r"system prompt",
    r"reveal your (instructions|prompt|rules)",
    r"act as (if|though)",
    r"new instructions?:",
    r"do not (follow|obey) (the|your) (system|original) prompt",
    r"jailbreak",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _SUSPICIOUS_PATTERNS]


@dataclass(frozen=True)
class PromptGuardResult:
    is_suspicious: bool
    matched_patterns: list[str]
    sanitized_text: str


def screen(text: str | None) -> PromptGuardResult:
    if not text:
        return PromptGuardResult(is_suspicious=False, matched_patterns=[], sanitized_text=text or "")

    matched = [p.pattern for p in _COMPILED if p.search(text)]
    if not matched:
        return PromptGuardResult(is_suspicious=False, matched_patterns=[], sanitized_text=text)

    sanitized = text
    for pattern in _COMPILED:
        sanitized = pattern.sub("[REDACTED-POSSIBLE-PROMPT-INJECTION]", sanitized)

    return PromptGuardResult(is_suspicious=True, matched_patterns=matched, sanitized_text=sanitized)
