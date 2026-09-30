from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.schemas.investigation_out import ApproveRejectRequest, ResponseActionOut
from app.services import audit

router = APIRouter(prefix="/api/response", tags=["response"])


def _get_actions(db: Session, investigation_id: str) -> list[ResponseAction]:
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(status_code=404, detail="investigation not found")
    return db.query(ResponseAction).filter(ResponseAction.investigation_id == investigation_id).all()


@router.get("/{investigation_id}", response_model=list[ResponseActionOut])
def list_response_actions(investigation_id: str, db: Session = Depends(get_db)):
    return _get_actions(db, investigation_id)


@router.post("/{investigation_id}/approve", response_model=list[ResponseActionOut])
def approve_response(
    investigation_id: str, payload: ApproveRejectRequest, db: Session = Depends(get_db)
):
    actions = _get_actions(db, investigation_id)
    if not actions:
        raise HTTPException(status_code=404, detail="no response actions for this investigation")

    now = datetime.now(timezone.utc)
    for action in actions:
        if action.status != "recommended":
            continue
        action.status = "simulated_executed"
        action.approved_by = payload.approved_by
        action.approved_at = now
        action.simulated_result = f"[SIMULATED] '{action.action_type}' executed. No real system was modified."
        audit.record(
            db, actor=payload.approved_by, investigation_id=investigation_id,
            tool_called="simulated_response_execution",
            tool_input={"action": action.action_type},
            tool_result={"status": "simulated_executed"},
            decision="approved",
        )
    db.commit()
    for a in actions:
        db.refresh(a)
    return actions


@router.post("/{investigation_id}/reject", response_model=list[ResponseActionOut])
def reject_response(
    investigation_id: str, payload: ApproveRejectRequest, db: Session = Depends(get_db)
):
    actions = _get_actions(db, investigation_id)
    if not actions:
        raise HTTPException(status_code=404, detail="no response actions for this investigation")

    now = datetime.now(timezone.utc)
    for action in actions:
        if action.status != "recommended":
            continue
        action.status = "rejected"
        action.approved_by = payload.approved_by
        action.approved_at = now
        audit.record(
            db, actor=payload.approved_by, investigation_id=investigation_id,
            decision="rejected", tool_input={"action": action.action_type},
        )
    db.commit()
    for a in actions:
        db.refresh(a)
    return actions
