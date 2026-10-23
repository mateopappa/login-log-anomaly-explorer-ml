from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from login_anomaly.api.deps import db_session
from login_anomaly.persistence import repositories as repo

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("")
def list_cases(session: Session = Depends(db_session), limit: int = 50) -> list[dict[str, Any]]:
    rows = repo.list_cases(session, limit=min(limit, 200))
    out = []
    for case in rows:
        latest = case.runs[-1] if case.runs else None
        out.append(
            {
                "case_id": case.id,
                "dataset_id": case.dataset_id,
                "kind": case.case_kind,
                "priority": case.priority_hint,
                "status": case.status,
                "events": len(case.event_ids_json or []),
                "signals": len(case.signals_json or []),
                "verdict": latest.result.verdict if latest and latest.result else None,
                "mode": latest.mode if latest else None,
                "provider_id": latest.provider_id if latest else None,
                "review": latest.review.quality if latest and latest.review else None,
                "updated_at": case.updated_at.isoformat(),
            }
        )
    return out


@router.get("/{case_id}")
def get_case(case_id: str, session: Session = Depends(db_session)) -> dict[str, Any]:
    case = repo.get_case(session, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    events = repo.events_for_case(session, case)
    from login_anomaly.services.investigations import serialize_run

    return {
        "case_id": case.id,
        "dataset_id": case.dataset_id,
        "kind": case.case_kind,
        "priority": case.priority_hint,
        "status": case.status,
        "event_ids": case.event_ids_json,
        "signals": case.signals_json,
        "associations": case.associations_json,
        "events": [
            {
                "event_id": event.event_id,
                "timestamp_utc": event.timestamp_utc.isoformat(),
                "account_id": event.account_id,
                "source_ip": event.source_ip,
                "outcome": event.outcome,
                "country_code": event.country_code,
            }
            for event in events
        ],
        "investigations": [serialize_run(run) for run in case.runs],
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
    }
