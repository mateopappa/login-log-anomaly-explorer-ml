from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from login_anomaly.api.deps import db_session
from login_anomaly.evaluation.case_score import CaseScoreError, score_case_investigation
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.models import DatasetRow, EvaluationRunRow

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


@router.post("/{case_id}/evaluate")
def evaluate_case(
    case_id: str,
    session: Session = Depends(db_session),
    run_id: str | None = Query(default=None, description="Investigation run to score; defaults to latest completed"),
) -> dict[str, Any]:
    """Offline score for one case investigation vs rebuilt ground truth.

    Labels are joined only here — never during detect/investigate.
    """
    case = repo.get_case(session, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

    runs = [run for run in case.runs if run.status == "completed" and run.result is not None]
    if run_id:
        run = next((item for item in runs if item.id == run_id), None)
        if run is None:
            raise HTTPException(status_code=404, detail="completed investigation run not found")
    else:
        run = runs[-1] if runs else None
        if run is None:
            raise HTTPException(status_code=409, detail="investigate the case before evaluating it")

    dataset = session.get(DatasetRow, case.dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail="dataset not found for case")

    events = repo.events_for_case(session, case)
    if not events:
        raise HTTPException(status_code=409, detail="case has no persisted events to score")

    assert run.result is not None
    try:
        metrics = score_case_investigation(
            case_id=case.id,
            event_ids=list(case.event_ids_json),
            priority_hint=case.priority_hint,
            case_kind=case.case_kind,
            first_seen=min(event.timestamp_utc for event in events),
            last_seen=max(event.timestamp_utc for event in events),
            verdict=run.result.verdict,
            confidence=float(run.result.confidence),
            justification=run.result.justification,
            limitations=list(run.result.limitations_json or []),
            evidence=list(run.result.evidence_json or []),
            tool_calls=[
                {
                    "tool_name": call.tool_name,
                    "arguments": call.arguments_json,
                    "status": call.status,
                }
                for call in run.tool_calls
            ],
            seed=dataset.seed,
            dataset_config=dict(dataset.config_json or {}),
        )
    except CaseScoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    evaluation_id = f"case-eval-{uuid.uuid4().hex[:12]}"
    session.add(
        EvaluationRunRow(
            id=evaluation_id,
            kind="case",
            seed=dataset.seed,
            config_json={
                "case_id": case.id,
                "run_id": run.id,
                "dataset_id": case.dataset_id,
                "provider_id": run.provider_id,
                "mode": run.mode,
            },
            metrics_json=metrics,
            created_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return {
        "evaluation_id": evaluation_id,
        "case_id": case.id,
        "run_id": run.id,
        "provider_id": run.provider_id,
        "mode": run.mode,
        "metrics": metrics,
    }
