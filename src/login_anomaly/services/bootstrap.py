"""Seed a reproducible demo dataset into the database (label-free runtime path)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from login_anomaly.correlation import InvestigationCase
from login_anomaly.persistence import repositories as repo
from login_anomaly.services.app_state import AppState
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow


def seed_demo(session: Session, state: AppState, *, seed: int = 42) -> dict[str, object]:
    """Generate events, run detectors/cases with mock investigator, persist everything."""
    plan = ScenarioPlan(
        bruteforce_campaigns=2,
        password_spraying_campaigns=1,
        impossible_travel_campaigns=2,
        benign_travelers=2,
    )
    config = GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_hours=72,
        n_accounts=50,
        n_events=1200,
    )
    dataset = generate(config, plan)
    model = state.ensure_model()
    workflow = run_detection_workflow(dataset, model, ModelRunMetadata("api-rf-baseline"))

    from login_anomaly.persistence.repositories import _jsonable

    repo.upsert_dataset(
        session,
        workflow.dataset_id,
        seed,
        _jsonable({"generator": asdict(config), "plan": asdict(plan), "model_run_id": "api-rf-baseline"}),
    )
    repo.replace_events(session, workflow.dataset_id, dataset.events)

    for case in workflow.cases:
        repo.upsert_case(session, case, status="open")

    # Persist initial mock investigations already produced by the workflow.
    from login_anomaly.agentic.reviewer import review_case_investigation
    from login_anomaly.config import CONFIG_VERSION

    for run in workflow.case_investigations:
        review = next((item for item in workflow.case_reviews if item.case_id == run.case.case_id), None)
        if review is None:
            review = review_case_investigation(run)
        row = repo.create_run(
            session,
            case_id=run.case.case_id,
            mode=run.mode,
            provider_id=run.provider_id,
            model=None,
            config_version=CONFIG_VERSION,
            idempotency_key=f"seed-{workflow.dataset_id}-{run.case.case_id}",
        )
        repo.mark_run_running(session, row)
        repo.persist_completed_run(
            session,
            row,
            run,
            review,
            latency_ms=0,
            risk_level=_risk_for(run.result.verdict),
            hypotheses=[],
        )

    state.last_seed_dataset_id = workflow.dataset_id
    session.flush()
    return {
        "dataset_id": workflow.dataset_id,
        "events": len(dataset.events),
        "cases": len(workflow.cases),
        "rule_alerts": len(workflow.rule_alerts),
        "ml_signals": len(workflow.ml_positive_signals),
    }


def _risk_for(verdict: str) -> str:
    if verdict == "malicious":
        return "high"
    if verdict == "benign":
        return "low"
    return "medium"


def _parse_dt(value: object) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise TypeError(f"unsupported datetime value: {type(value)!r}")


def case_from_row_signals(case_id: str, dataset_id: str, case_kind: str, priority: str, event_ids: list, signals: list, associations: list) -> InvestigationCase:
    """Rebuild a minimal InvestigationCase from persisted JSON for re-investigation."""
    from login_anomaly.correlation import Association, MlPositiveSignal, RuleAlertSignal

    rebuilt_signals = []
    for item in signals:
        if "rule_id" in item:
            rebuilt_signals.append(
                RuleAlertSignal(
                    signal_id=item["signal_id"],
                    alert_id=item["alert_id"],
                    rule_id=item["rule_id"],
                    severity=item["severity"],
                    event_ids=tuple(item["event_ids"]),
                    first_seen=_parse_dt(item["first_seen"]),
                    last_seen=_parse_dt(item["last_seen"]),
                    explanation=item["explanation"],
                    evidence=tuple(item["evidence"]),
                )
            )
        else:
            rebuilt_signals.append(
                MlPositiveSignal(
                    signal_id=item["signal_id"],
                    dataset_id=item["dataset_id"],
                    event_id=item["event_id"],
                    model_run_id=item["model_run_id"],
                    threshold=item["threshold"],
                    score=item.get("score"),
                )
            )
    rebuilt_assoc = tuple(
        Association(
            ml_signal_id=item["ml_signal_id"],
            rule_signal_id=item.get("rule_signal_id"),
            event_id=item["event_id"],
            basis=item["basis"],
            candidate_rule_signal_ids=tuple(item["candidate_rule_signal_ids"]),
        )
        for item in associations
    )
    return InvestigationCase(
        case_id=case_id,
        dataset_id=dataset_id,
        case_kind=case_kind,  # type: ignore[arg-type]
        event_ids=tuple(event_ids),
        signals=tuple(rebuilt_signals),
        associations=rebuilt_assoc,
        priority_hint=priority,  # type: ignore[arg-type]
    )
