from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.api.schemas import InvestigateRequest
from login_anomaly.persistence import repositories as repo
from login_anomaly.services.app_state import AppState
from login_anomaly.services.investigations import InvestigationServiceError, serialize_run, start_investigation

router = APIRouter(tags=["investigations"])


@router.post("/cases/{case_id}/investigations")
async def create_investigation(
    case_id: str,
    body: InvestigateRequest,
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
) -> dict[str, Any]:
    """Run investigation off the event loop (mock is fast; Haiku can block)."""

    def _run():
        return start_investigation(
            session,
            state,
            case_id,
            provider_name=body.provider,
            idempotency_key=body.idempotency_key,
        )

    try:
        run = await asyncio.to_thread(_run)
    except InvestigationServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    return serialize_run(run)


@router.get("/investigations/{run_id}")
def get_investigation(run_id: str, session: Session = Depends(db_session)) -> dict[str, Any]:
    run = repo.get_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="investigation run not found")
    return serialize_run(run)
