"""Persist SOC Live cases, events, and investigations so dossiers survive API restart."""

from __future__ import annotations

import hashlib
from dataclasses import asdict

from sqlalchemy.orm import Session

from login_anomaly.config import CONFIG_VERSION
from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.live.engine import SimulationService
from login_anomaly.persistence import repositories as repo
from login_anomaly.services.bootstrap import _risk_for


def _event_from_row(row: dict) -> AuthEvent:
    ts = row["timestamp_utc"]
    if isinstance(ts, str):
        from datetime import datetime

        parsed = datetime.fromisoformat(ts)
        if parsed.tzinfo is None:
            from datetime import timezone

            parsed = parsed.replace(tzinfo=timezone.utc)
        ts = parsed
    return AuthEvent(
        event_id=row["event_id"],
        timestamp_utc=ts,
        account_id=row["account_id"],
        source_ip=row["source_ip"],
        outcome=Outcome(row["outcome"]),
        country_code=row["country_code"],
    )


def persist_live_snapshot(session: Session, service: SimulationService) -> dict[str, int]:
    """Upsert the live simulation dataset, retained/case events, cases, and completed runs."""
    dataset_id = service.simulation_id
    summary = service.summary()
    repo.upsert_dataset(
        session,
        dataset_id,
        int(summary.get("seed") or 0),
        {
            "source": "soc_live",
            "mode": summary.get("mode"),
            "scenario": summary.get("scenario"),
            "attacks": summary.get("attacks"),
            "enable_rules": summary.get("enable_rules"),
            "enable_ml": summary.get("enable_ml"),
        },
    )

    by_id: dict[str, AuthEvent] = {event.event_id: event for event in getattr(service, "_buffer", [])}
    for record in getattr(service, "_cases", {}).values():
        for row in record.events:
            event = _event_from_row(row)
            by_id[event.event_id] = event
    if by_id:
        # Merge with existing DB events for this dataset (live grows over time).
        existing = {event.event_id: event for event in repo.load_auth_events(session, dataset_id)}
        existing.update(by_id)
        repo.replace_events(session, dataset_id, tuple(existing.values()))

    cases_written = 0
    runs_written = 0
    active = getattr(service, "_active_case_ids", set())
    for record in getattr(service, "_cases", {}).values():
        status = "open" if record.case.case_id in active else "closed"
        repo.upsert_case(session, record.case, status=status)
        cases_written += 1
        if record.run is None or record.review is None:
            continue
        fingerprint = hashlib.sha256(",".join(record.case.event_ids).encode("utf-8")).hexdigest()[:12]
        idem = f"live-{dataset_id}-{record.case.case_id}-{fingerprint}"
        if repo.find_run_by_idempotency(session, idem) is not None:
            continue
        run_row = repo.create_run(
            session,
            case_id=record.case.case_id,
            mode=record.run.mode,
            provider_id=record.run.provider_id,
            model=None,
            config_version=CONFIG_VERSION,
            idempotency_key=idem,
        )
        repo.mark_run_running(session, run_row)
        repo.persist_completed_run(
            session,
            run_row,
            record.run,
            record.review,
            latency_ms=0,
            risk_level=record.run.result.risk_level or _risk_for(record.run.result.verdict),
            hypotheses=[asdict(item) for item in record.run.result.hypotheses],
        )
        runs_written += 1

    session.flush()
    return {"cases": cases_written, "runs": runs_written, "events": len(by_id)}
