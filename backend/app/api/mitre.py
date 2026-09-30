from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.mitre import atlas, attack

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/attack/{technique_id}")
def get_attack_technique(technique_id: str) -> dict:
    technique = attack.get_technique(technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail=f"ATT&CK technique '{technique_id}' not found")
    return technique


@router.get("/atlas/{technique_id}")
def get_atlas_technique(technique_id: str) -> dict:
    technique = atlas.get_technique(technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail=f"ATLAS technique '{technique_id}' not found")
    return technique
