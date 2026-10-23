from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.api.schemas import LiveControlRequest
from login_anomaly.live.engine import LiveConfig, SimulationService
from login_anomaly.live.sources import REPLAY_SCENARIOS
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
        "cases": service.cases()[:50],
        "persisted": persisted,
    }


@router.get("/status")
def live_status(state: AppState = Depends(app_state_dep)) -> dict[str, Any]:
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
            }
            for name, plan in REPLAY_SCENARIOS.items()
        },
        "notes": [
            "All traffic is synthetic and reproducible from the seed.",
            "Ground-truth labels are never available to detectors or investigators during the live run.",
            "Detectors, correlation, mock investigation, and deterministic review run on each advance batch.",
            "After each advance, open cases and completed investigations are upserted into the database.",
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
                service.reset()
                state.live = None
                return _snapshot(state)
            elif action == "advance":
                service.advance()
                persisted = persist_live_snapshot(session, service)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface persist races as 409, not opaque CORS 500
        raise HTTPException(status_code=409, detail=f"live control failed: {exc}") from exc

    return _snapshot(state, persisted=persisted)


@router.get("/cases")
def live_cases(state: AppState = Depends(app_state_dep)) -> list[dict[str, Any]]:
    if state.live is None:
        return []
    return state.live.cases()
