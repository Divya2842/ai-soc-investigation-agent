"""
Rule-based MITRE ATLAS mapper.

Deliberately independent from the ATT&CK mapper. ATLAS techniques only fire
when the evidence contains AI/ML/LLM-related signals — this function never
forces an ATLAS mapping onto a normal SOC alert. When nothing matches, the
caller should surface the explicit "No relevant MITRE ATLAS technique
identified." message rather than omitting the field, per the project
requirements.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
_DATASET_PATH = REPO_ROOT / "data" / "atlas" / "atlas_techniques.json"

_dataset_cache: list[dict[str, Any]] | None = None

NO_MATCH_MESSAGE = "No relevant MITRE ATLAS technique identified."


def _load_dataset() -> list[dict[str, Any]]:
    global _dataset_cache
    if _dataset_cache is None:
        with _DATASET_PATH.open("r", encoding="utf-8") as f:
            _dataset_cache = json.load(f)
    return _dataset_cache


@dataclass(frozen=True)
class AtlasMatch:
    technique_id: str
    name: str
    tactic: str
    rationale: str
    supporting_evidence: list[str]


def map_atlas(evidence_text: str) -> list[AtlasMatch]:
    text = evidence_text.lower()
    matches: list[AtlasMatch] = []

    for technique in _load_dataset():
        hits = [p for p in technique["ai_signal_patterns"] if p.lower() in text]
        if hits:
            matches.append(
                AtlasMatch(
                    technique_id=technique["technique_id"],
                    name=technique["name"],
                    tactic=technique["tactic"],
                    rationale=(
                        f"Evidence contains AI-security signal(s) associated with "
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
