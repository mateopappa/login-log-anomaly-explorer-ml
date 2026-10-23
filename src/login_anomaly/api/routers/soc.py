from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session, settings_dep
from login_anomaly.api.schemas import SeedRequest, SeedResponse, SocSummary
from login_anomaly.config import Settings
from login_anomaly.persistence import repositories as repo
from login_anomaly.services.app_state import AppState
from login_anomaly.services.bootstrap import seed_demo
from login_anomaly.services.providers import provider_status

router = APIRouter(prefix="/soc", tags=["soc"])


@router.get("/summary", response_model=SocSummary)
def summary(
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
    settings: Settings = Depends(settings_dep),
) -> SocSummary:
    cases = repo.list_cases(session, limit=20)
    recent = []
    for case in cases:
        latest = case.runs[-1] if case.runs else None
        recent.append(
            {
                "case_id": case.id,
                "kind": case.case_kind,
                "priority": case.priority_hint,
                "status": case.status,
                "events": len(case.event_ids_json or []),
                "verdict": latest.result.verdict if latest and latest.result else None,
                "mode": latest.mode if latest else None,
                "review": latest.review.quality if latest and latest.review else None,
            }
        )
    live_payload = None
    if state.live is not None:
        live_payload = state.live.summary()
    return SocSummary(
        cases_open=sum(1 for case in cases if case.status == "open"),
        cases_total=len(cases),
        recent_cases=recent,
        live=live_payload,
        investigator=provider_status(settings),
        services={
            "api": "ok",
            "database": "ok",
            "live": "running" if state.live and state.live.state.value == "running" else "idle",
        },
    )


@router.post("/seed", response_model=SeedResponse)
def seed(
    body: SeedRequest,
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
) -> SeedResponse:
    result = seed_demo(session, state, seed=body.seed)
    return SeedResponse(**result)  # type: ignore[arg-type]


@router.get("/data-explainer")
def data_explainer() -> dict[str, object]:
    """How demo/batch synthetic data is produced (no labels exposed)."""
    return {
        "title": "How synthetic authentication data is generated",
        "summary": (
            "The generator builds a reproducible AuthEvent stream from a seed and a campaign plan. "
            "Detectors and investigators only see observable fields (time, account, IP, outcome, country). "
            "Ground-truth labels exist only for offline evaluation and never enter the runtime tools."
        ),
        "seed_demo_defaults": {
            "duration_hours": 72,
            "n_accounts": 50,
            "n_events": 1200,
            "bruteforce_campaigns": 2,
            "password_spraying_campaigns": 1,
            "impossible_travel_campaigns": 2,
            "benign_travelers": 2,
        },
        "campaign_types": [
            {
                "id": "bruteforce",
                "name": "Bruteforce",
                "description": "Many failures on one account from one IP inside a short window, sometimes followed by a success.",
            },
            {
                "id": "password_spraying",
                "name": "Password spraying",
                "description": "One IP tries a few failures across many accounts inside a wider window.",
            },
            {
                "id": "impossible_travel",
                "name": "Impossible travel",
                "description": "A home-country success followed soon by a success from another country for the same account.",
            },
            {
                "id": "benign_travelers",
                "name": "Benign travelers",
                "description": "Legitimate country changes that should not be treated as attacks by themselves.",
            },
        ],
        "pipeline": [
            "generate(seed, plan) → observable events",
            "rules + ML detectors (independent)",
            "exact event-id correlation → cases",
            "bounded investigator (mock or Claude Haiku) + deterministic reviewer",
            "evaluation may join ground truth only after the run",
        ],
        "live_vs_seed": {
            "seed_demo": "Batch snapshot persisted to the database for the Cases workbench.",
            "soc_live": "Time-released stream in-process. Call advance (the UI can auto-tick) to release events.",
        },
    }
