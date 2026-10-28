from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.services.app_state import AppState
from login_anomaly.evaluation.case_score import CaseScoreError, score_case_investigation
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.models import DatasetRow, EvaluationRunRow

router = APIRouter(prefix="/cases", tags=["cases"])


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_ids_for_score(case: Any, run: Any) -> list[str]:
    """Score the ids the run saw. Refuse when the case grew after that run."""
    current = [str(item) for item in (case.event_ids_json or [])]
    stored = [str(item) for item in run.event_ids_json] if run.event_ids_json else None
    if stored is not None:
        if sorted(stored) != sorted(current):
            raise HTTPException(status_code=409, detail="case evidence changed since this run; investigate again")
        return stored
    completed = run.completed_at
    if completed is not None and _aware(case.updated_at) > _aware(completed):
        raise HTTPException(status_code=409, detail="case evidence changed since this run; investigate again")
    return current


@router.get("")
def list_cases(
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
    limit: int = Query(default=200, ge=1, le=200),
    scope: str = Query(default="latest", pattern="^(sites|latest|live|all)$"),
) -> list[dict[str, Any]]:
    dataset_id: str | None = None
    dataset_ids: list[str] | None = None
    site_names: dict[str, str] = {}
    status: str | None = None
    if scope == "sites":
        sites = repo.latest_site_datasets(session)
        dataset_ids = [row.id for row in sites]
        site_names = {row.id: str((row.config_json or {}).get("display_name") or "") for row in sites}
        if not dataset_ids:
            return []
    elif scope == "live":
        with state.lock:
            live = state.live
            dataset_id = live.simulation_id if live is not None else None
        if dataset_id is None:
            return []
        status = "open"
    elif scope != "all":
        dataset = repo.latest_batch_dataset(session)
        if dataset is None:
            return []
        dataset_id = dataset.id
    rows = repo.list_cases(
        session,
        limit=limit,
        dataset_id=dataset_id,
        dataset_ids=dataset_ids,
        status=status,
    )
    if scope == "live":
        rows = [case for case in rows if case.priority_hint != "rule_high"]
    out = []
    for case in rows:
        latest = case.runs[-1] if case.runs else None
        out.append(
            {
                "case_id": case.id,
                "dataset_id": case.dataset_id,
                "site": site_names.get(case.dataset_id),
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

    event_ids = _event_ids_for_score(case, run)
    assert run.result is not None
    try:
        metrics = score_case_investigation(
            case_id=case.id,
            event_ids=event_ids,
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
