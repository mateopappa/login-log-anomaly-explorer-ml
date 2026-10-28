from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.api.schemas import LiveControlRequest
from login_anomaly.evaluation.live import evaluate_live_replay
from login_anomaly.live.engine import LiveConfig, SimulationService
from login_anomaly.live.sources import REPLAY_SCENARIOS
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.models import EvaluationRunRow
from login_anomaly.services.app_state import AppState
from login_anomaly.services.live_persist import persist_live_snapshot

router = APIRouter(prefix="/live", tags=["live"])


def _snapshot(state: AppState, *, persisted: dict[str, int] | None = None) -> dict[str, Any]:
    if state.live is None:
        return {
            "active": False,
            "state": "idle",
            "message": "No live session. Start a replay or continuous run.",
            "scenarios": list(REPLAY_SCENARIOS.keys()),
            "summary": None,
            "recent_events": [],
            "activity": [],
            "alerts": [],
            "cases": [],
            "persisted": persisted,
        }
    service = state.live
    return {
        "active": True,
        "state": service.state.value,
        "message": service.summary().get("message"),
        "scenarios": list(REPLAY_SCENARIOS.keys()),
        "summary": service.summary(),
        "recent_events": service.recent_events()[:40],
        "activity": service.activity()[:40],
        "alerts": service.alerts()[:40],
        "cases": service.cases(),
        "persisted": persisted,
    }


@router.get("/status")
def live_status(state: AppState = Depends(app_state_dep)) -> dict[str, Any]:
    with state.lock:
        return _snapshot(state)


@router.get("/meta")
def live_meta() -> dict[str, Any]:
    """Static explanation of how live synthetic traffic is produced."""
    return {
        "engine": "Synchronous SimulationService. The UI (or a client) must call advance; there is no background broker.",
        "modes": {
            "replay": "Generate a fixed scenario up front (seeded), then release events in order over simulated time.",
            "continuous": "Generate independent 3-hour chunks on demand. Account/IP history does not carry across chunks.",
        },
        "replay_scenarios": {
            name: {
                "bruteforce_campaigns": plan.bruteforce_campaigns,
                "password_spraying_campaigns": plan.password_spraying_campaigns,
                "impossible_travel_campaigns": plan.impossible_travel_campaigns,
                "benign_travelers": plan.benign_travelers,
                "benign_decoys": plan.benign_decoys,
                "ranges": "hard" if name == "Boundary lab" else "nominal",
            }
            for name, plan in REPLAY_SCENARIOS.items()
        },
        "notes": [
            "All traffic is synthetic and reproducible from the seed.",
            "Ground-truth labels are never available to detectors or investigators during the live run.",
            "Detectors and correlation run on each advance batch and file cases with a priority.",
            "Investigations stay manual. After each advance, open cases are upserted into the database.",
        ],
    }


@router.post("/control")
def live_control(
    body: LiveControlRequest,
    state: AppState = Depends(app_state_dep),
    session: Session = Depends(db_session),
) -> dict[str, Any]:
    action = body.action
    persisted: dict[str, int] | None = None
    with state.lock:
        try:
            if action == "start":
                if body.mode is None or body.seed is None:
                    raise HTTPException(status_code=400, detail="mode and seed are required to start")
                if body.mode == "replay" and body.scenario and body.scenario not in REPLAY_SCENARIOS:
                    raise HTTPException(status_code=400, detail=f"unknown scenario: {body.scenario}")
                rate = 5.0 if body.events_per_second is None else float(body.events_per_second)
                config = LiveConfig(
                    mode=body.mode,
                    seed=body.seed,
                    scenario=body.scenario or "Mixed campaigns",
                    events_per_second=rate,
                    enable_rules=body.enable_rules,
                    enable_ml=body.enable_ml,
                )
                model = state.ensure_model()
                state.live = SimulationService(config, model)
                state.live.start()
                persisted = persist_live_snapshot(session, state.live)
            else:
                if state.live is None:
                    raise HTTPException(status_code=409, detail="live simulation is not active")
                service = state.live
                if action == "pause":
                    service.pause()
                elif action == "resume":
                    service.resume()
                elif action == "stop":
                    service.stop()
                    persisted = persist_live_snapshot(session, service)
                elif action == "reset":
                    dataset_id = service.simulation_id
                    service.reset()
                    state.live = None
                    repo.delete_cases_for_dataset(session, dataset_id)
                elif action == "advance":
                    service.advance()
                    persisted = persist_live_snapshot(session, service)
            # Commit before releasing the lock so the next tick cannot insert the same rows.
            session.commit()
        except HTTPException:
            session.rollback()
            raise
        except ValueError as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 — surface persist races as 409, not opaque CORS 500
            session.rollback()
            raise HTTPException(status_code=409, detail=f"live control failed: {exc}") from exc

        return _snapshot(state, persisted=persisted)


@router.post("/score")
def score_live(
    state: AppState = Depends(app_state_dep),
    session: Session = Depends(db_session),
) -> dict[str, Any]:
    """Score the running or finished replay, and the investigations stored for it.

    Ground truth is rebuilt here and is not returned to the investigator.
    """
    with state.lock:
        service = state.live
        if service is None:
            raise HTTPException(status_code=409, detail="live simulation is not active")
        if service.config.mode != "replay":
            raise HTTPException(status_code=400, detail="only a replay can be scored against one ground truth")
        dataset_id = service.simulation_id
        if service.released == 0:
            raise HTTPException(status_code=409, detail="replay has not released any events yet")

    cases = repo.list_cases(session, limit=1000, dataset_id=dataset_id, status="open")
    cases = [case for case in cases if case.priority_hint != "rule_high"]
    investigated: list[tuple[str, list[str]]] = []
    awaiting = 0
    for case in cases:
        latest = next((run for run in reversed(case.runs) if run.result is not None), None)
        if latest is None or latest.result is None:
            awaiting += 1
            continue
        investigated.append((latest.result.verdict, [str(item) for item in (case.event_ids_json or [])]))

    with state.lock:
        service = state.live
        if service is None or service.simulation_id != dataset_id:
            raise HTTPException(status_code=409, detail="live simulation changed while scoring")
        try:
            result = evaluate_live_replay(service, investigated=investigated, awaiting=awaiting)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        partial = service.summary()["pending"] > 0

    payload = result.to_dict()
    payload["partial"] = partial
    payload["note"] = (
        "Scored on the events released so far. Ground truth was rebuilt offline and was not shown to the investigator."
        if partial
        else "Ground truth was rebuilt offline from this replay's seed and scenario, and was not shown to the investigator."
    )
    run_id = f"live-eval-{uuid.uuid4().hex[:12]}"
    session.add(
        EvaluationRunRow(
            id=run_id,
            kind="live_replay",
            seed=result.seed,
            config_json={"simulation_id": result.simulation_id, "scenario": result.scenario, "partial": partial},
            metrics_json=payload,
            created_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return {"evaluation_id": run_id, "metrics": payload}


@router.get("/cases")
def live_cases(state: AppState = Depends(app_state_dep)) -> list[dict[str, Any]]:
    with state.lock:
        if state.live is None:
            return []
        return state.live.cases()
