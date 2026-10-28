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
    sites = repo.latest_site_datasets(session)
    site_ids = [row.id for row in sites]
    dataset = None if site_ids else repo.latest_batch_dataset(session)
    dataset_id = dataset.id if dataset is not None else None
    recent = []
    open_rows = (
        repo.list_cases(session, limit=8, dataset_ids=site_ids, status="open")
        if site_ids
        else repo.list_cases(session, limit=8, dataset_id=dataset_id, status="open")
        if dataset_id
        else []
    )
    if open_rows:
        for case in open_rows:
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
    with state.lock:
        live_payload = state.live.summary() if state.live is not None else None
        live_id = state.live.simulation_id if state.live is not None else None
        live_state = state.live.state.value if state.live is not None else "idle"
    if site_ids:
        cases_open = sum(repo.count_cases(session, item, status="open") for item in site_ids)
        cases_total = sum(repo.count_cases(session, item) for item in site_ids)
        events_total = sum(repo.count_events(session, item) for item in site_ids)
        by_kind: dict[str, int] = {}
        for item in site_ids:
            for kind, count in repo.cases_by_kind(session, item).items():
                by_kind[kind] = by_kind.get(kind, 0) + count
        summary_scope = "sites"
        active_id = None
        active_seed = None
    else:
        cases_open = repo.count_cases(session, dataset_id, status="open") if dataset_id else 0
        cases_total = repo.count_cases(session, dataset_id) if dataset_id else 0
        events_total = repo.count_events(session, dataset_id) if dataset_id else 0
        by_kind = repo.cases_by_kind(session, dataset_id) if dataset_id else {}
        summary_scope = "latest"
        active_id = dataset_id
        active_seed = dataset.seed if dataset is not None else None
    return SocSummary(
        cases_open=cases_open,
        cases_total=cases_total,
        recent_cases=recent,
        live=live_payload,
        investigator=provider_status(settings),
        services={
            "api": "ok",
            "database": "ok",
            "live": "running" if live_state == "running" else "idle",
        },
        active_dataset_id=active_id,
        active_seed=active_seed,
        events_total=events_total,
        cases_by_kind=by_kind,
        scope=summary_scope,
        live_dataset_id=live_id,
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
            "n_events": 1800,
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
            "tool-gated investigator (mock or Claude Haiku) + deterministic reviewer",
            "labels may join only after the run for scoring",
        ],
        "live_vs_seed": {
            "seed_demo": "Batch snapshot persisted to the database for the Cases workbench.",
            "soc_live": "Time-released stream in-process. Call advance (the UI can auto-tick) to release events.",
        },
    }
