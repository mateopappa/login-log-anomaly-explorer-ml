from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.api.schemas import EvaluationRequest
from login_anomaly.evaluation.api_benchmark import run_offline_benchmark
from login_anomaly.persistence.models import EvaluationRunRow
from login_anomaly.services.app_state import AppState
from login_anomaly.services.providers import resolve_provider

router = APIRouter(prefix="/evaluations", tags=["evaluations"])


@router.post("/benchmark")
def run_benchmark(
    body: EvaluationRequest,
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
) -> dict[str, Any]:
    """Offline benchmark. Ground truth is accessed only inside evaluation.api_benchmark."""
    try:
        provider = resolve_provider(state.settings, body.provider)
    except LookupError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    metrics = run_offline_benchmark(seed=body.seed, model=state.ensure_model(), provider=provider)
    run_id = f"eval-{uuid.uuid4().hex[:12]}"
    session.add(
        EvaluationRunRow(
            id=run_id,
            kind="benchmark",
            seed=body.seed,
            config_json={"provider": body.provider, **metrics.get("config", {})},
            metrics_json=metrics,
            created_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return {"evaluation_id": run_id, "seed": body.seed, "metrics": metrics}


@router.get("")
def list_evaluations(session: Session = Depends(db_session), limit: int = 20) -> list[dict[str, Any]]:
    from sqlalchemy import select

    rows = session.scalars(select(EvaluationRunRow).order_by(EvaluationRunRow.created_at.desc()).limit(limit)).all()
    return [
        {
            "evaluation_id": row.id,
            "kind": row.kind,
            "seed": row.seed,
            "config": row.config_json,
            "metrics": row.metrics_json,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]
