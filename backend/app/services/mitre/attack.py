"""
Rule-based MITRE ATT&CK mapper.

The LLM is never allowed to invent technique IDs. This module loads a local
curated dataset (data/mitre/attack_techniques.json) and matches it against
evidence text using simple, auditable substring matching. Every match
carries the exact evidence string that triggered it, so the "why it
matches" shown in the UI is never fabricated.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
_DATASET_PATH = REPO_ROOT / "data" / "mitre" / "attack_techniques.json"

_dataset_cache: list[dict[str, Any]] | None = None


def _load_dataset() -> list[dict[str, Any]]:
    global _dataset_cache
    if _dataset_cache is None:
        with _DATASET_PATH.open("r", encoding="utf-8") as f:
            _dataset_cache = json.load(f)
    return _dataset_cache


@dataclass(frozen=True)
class AttackMatch:
    technique_id: str
    name: str
    tactic: str
    rationale: str
    supporting_evidence: list[str]


def map_attack(evidence_text: str) -> list[AttackMatch]:
    """
    evidence_text: a lowercased blob combining alert description,
    command_line, log payloads, etc. Callers are responsible for building
    this from actual evidence — this function does no evidence gathering
    itself, only matching.
    """
    text = evidence_text.lower()
    matches: list[AttackMatch] = []

    for technique in _load_dataset():
        hits = [p for p in technique["match_patterns"] if p.lower() in text]
        if hits:
            matches.append(
                AttackMatch(
                    technique_id=technique["technique_id"],
                    name=technique["name"],
                    tactic=technique["tactic"],
                    rationale=(
                        f"Evidence contains pattern(s) associated with "
                        f"{technique['name']}: {', '.join(hits)}"
                    ),
                    supporting_evidence=hits,
                )
            )
    return matches


def get_technique(technique_id: str) -> dict[str, Any] | None:
    for technique in _load_dataset():
        if technique["technique_id"] == technique_id:
            return technique
    return None
