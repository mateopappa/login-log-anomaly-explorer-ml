"""Persistence helpers that map domain objects to ORM rows."""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, selectinload

from login_anomaly.agentic.case_investigator import CaseInvestigationRun
from login_anomaly.agentic.contracts import InvestigationResult
from login_anomaly.agentic.reviewer import InvestigationReview
from login_anomaly.correlation import InvestigationCase, MlPositiveSignal, RuleAlertSignal
from login_anomaly.events import AuthEvent
from login_anomaly.persistence.models import (
    CaseRow,
    DatasetRow,
    EventRow,
    InvestigationResultRow,
    InvestigationRunRow,
    ReviewRow,
    ToolCallRow,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value


def _signal_to_dict(signal: RuleAlertSignal | MlPositiveSignal) -> dict[str, Any]:
    return _jsonable(asdict(signal))


def upsert_dataset(session: Session, dataset_id: str, seed: int, config: dict[str, Any]) -> DatasetRow:
    row = session.get(DatasetRow, dataset_id)
    if row is None:
        row = DatasetRow(id=dataset_id, seed=seed, config_json=config, created_at=_utcnow())
        session.add(row)
    return row


def _add_event(session: Session, dataset_id: str, event: AuthEvent) -> None:
    session.add(
        EventRow(
            dataset_id=dataset_id,
            event_id=event.event_id,
            timestamp_utc=event.timestamp_utc,
            account_id=event.account_id,
            source_ip=event.source_ip,
            outcome=event.outcome.value,
            country_code=event.country_code,
        )
    )


def replace_events(session: Session, dataset_id: str, events: tuple[AuthEvent, ...]) -> None:
    """Replace all events for a dataset. Dedupes by event_id (last write wins)."""
    from sqlalchemy import delete

    session.execute(delete(EventRow).where(EventRow.dataset_id == dataset_id))
    session.flush()
    for event in {event.event_id: event for event in events}.values():
        _add_event(session, dataset_id, event)


def insert_events(session: Session, dataset_id: str, events: tuple[AuthEvent, ...]) -> None:
    """Insert event ids that are not already stored. Does not delete."""
    if not events:
        return
    existing = set(
        session.scalars(select(EventRow.event_id).where(EventRow.dataset_id == dataset_id)).all()
    )
    for event in events:
        if event.event_id in existing:
            continue
        existing.add(event.event_id)
        _add_event(session, dataset_id, event)


def upsert_case(session: Session, case: InvestigationCase, *, status: str = "open") -> CaseRow:
    row = session.get(CaseRow, case.case_id)
    # Skip the write when the queue would not change. Live calls this every tick.
    if (
        row is not None
        and row.status == status
        and row.case_kind == case.case_kind
        and row.priority_hint == case.priority_hint
        and list(row.event_ids_json or []) == list(case.event_ids)
    ):
        return row
    now = _utcnow()
    payload = {
        "dataset_id": case.dataset_id,
        "case_kind": case.case_kind,
        "priority_hint": case.priority_hint,
        "status": status,
        "event_ids_json": list(case.event_ids),
        "signals_json": [_signal_to_dict(signal) for signal in case.signals],
        "associations_json": [_jsonable(asdict(item)) for item in case.associations],
        "updated_at": now,
    }
    if row is None:
        row = CaseRow(id=case.case_id, created_at=now, **payload)
        session.add(row)
        return row
    for key, value in payload.items():
        setattr(row, key, value)
    return row


def find_run_by_idempotency(session: Session, key: str) -> InvestigationRunRow | None:
    return session.scalar(select(InvestigationRunRow).where(InvestigationRunRow.idempotency_key == key))


def create_run(
    session: Session,
    *,
    case_id: str,
    mode: str,
    provider_id: str,
    model: str | None,
    config_version: str,
    idempotency_key: str | None,
) -> InvestigationRunRow:
    run = InvestigationRunRow(
        id=f"run-{uuid.uuid4().hex[:16]}",
        case_id=case_id,
        status="queued",
        mode=mode,
        provider_id=provider_id,
        model=model,
        config_version=config_version,
        idempotency_key=idempotency_key,
        steps=0,
        errors_json=[],
        created_at=_utcnow(),
    )
    session.add(run)
    session.flush()
    return run


def mark_run_running(session: Session, run: InvestigationRunRow) -> None:
    run.status = "running"
    session.flush()


def persist_completed_run(
    session: Session,
    run: InvestigationRunRow,
    investigation: CaseInvestigationRun,
    review: InvestigationReview,
    *,
    latency_ms: int,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    cost_usd_est: float | None = None,
    risk_level: str | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
) -> InvestigationRunRow:
    result = investigation.result
    run.status = "completed" if not investigation.errors else "completed"
    run.steps = investigation.steps
    run.errors_json = list(investigation.errors)
    run.latency_ms = latency_ms
    run.tokens_in = tokens_in
    run.tokens_out = tokens_out
    run.cost_usd_est = cost_usd_est
    run.completed_at = _utcnow()
    run.event_ids_json = list(investigation.case.event_ids)

    for existing in list(run.tool_calls):
        session.delete(existing)
    if run.result is not None:
        session.delete(run.result)
    if run.review is not None:
        session.delete(run.review)
    session.flush()

    for seq, call in enumerate(result.tool_calls):
        session.add(
            ToolCallRow(
                run_id=run.id,
                seq=seq,
                tool_name=call.tool_name,
                arguments_json=dict(call.arguments),
                status=call.status,
                result_summary=None,
                duration_ms=None,
            )
        )
    session.add(
        InvestigationResultRow(
            run_id=run.id,
            verdict=result.verdict,
            confidence=float(result.confidence),
            risk_level=risk_level,
            justification=result.justification,
            limitations_json=list(result.limitations),
            evidence_json=[asdict(item) for item in result.evidence],
            hypotheses_json=hypotheses or [],
        )
    )
    session.add(
        ReviewRow(
            run_id=run.id,
            mode=review.mode,
            quality=review.quality,
            payload_json=asdict(review),
        )
    )
    session.flush()
    return run


def mark_run_failed(session: Session, run: InvestigationRunRow, error: str, *, latency_ms: int | None = None) -> None:
    run.status = "failed"
    run.errors_json = list(run.errors_json or []) + [error]
    run.latency_ms = latency_ms
    run.completed_at = _utcnow()
    session.flush()


def _dataset_source(row: DatasetRow) -> str | None:
    source = (row.config_json or {}).get("source")
    return str(source) if source is not None else None


def _latest_by_source(session: Session, *, live: bool) -> DatasetRow | None:
    # Few datasets in a demo. Filtering in Python avoids a JSON dialect split.
    # Site publishes are their own queue, not "the latest batch".
    for row in session.scalars(select(DatasetRow).order_by(DatasetRow.created_at.desc())).all():
        source = _dataset_source(row)
        if source == "site":
            continue
        if (source == "soc_live") == live:
            return row
    return None


def site_datasets(session: Session) -> list[DatasetRow]:
    rows = session.scalars(select(DatasetRow).order_by(DatasetRow.created_at.desc())).all()
    return [row for row in rows if _dataset_source(row) == "site"]


def latest_site_datasets(session: Session) -> list[DatasetRow]:
    """Newest publish per site. Older cycles stay in the database for scope=all."""
    seen: set[str] = set()
    picked: list[DatasetRow] = []
    for row in site_datasets(session):
        tenant = str((row.config_json or {}).get("tenant_id") or row.id)
        if tenant in seen:
            continue
        seen.add(tenant)
        picked.append(row)
    return picked


def latest_batch_dataset(session: Session) -> DatasetRow | None:
    return _latest_by_source(session, live=False)


def latest_live_dataset(session: Session) -> DatasetRow | None:
    return _latest_by_source(session, live=True)


def count_events(session: Session, dataset_id: str) -> int:
    stmt = select(func.count()).select_from(EventRow).where(EventRow.dataset_id == dataset_id)
    return int(session.scalar(stmt) or 0)


def count_cases(session: Session, dataset_id: str, *, status: str | None = None) -> int:
    stmt = select(func.count()).select_from(CaseRow).where(CaseRow.dataset_id == dataset_id)
    if status is not None:
        stmt = stmt.where(CaseRow.status == status)
    return int(session.scalar(stmt) or 0)


def cases_by_kind(session: Session, dataset_id: str) -> dict[str, int]:
    stmt = (
        select(CaseRow.case_kind, func.count())
        .where(CaseRow.dataset_id == dataset_id)
        .group_by(CaseRow.case_kind)
    )
    return {str(kind): int(count) for kind, count in session.execute(stmt).all()}


def delete_cases_for_dataset(session: Session, dataset_id: str) -> int:
    """Remove one simulation's cases and their investigations. Other datasets stay."""
    case_ids = list(session.scalars(select(CaseRow.id).where(CaseRow.dataset_id == dataset_id)))
    if not case_ids:
        return 0
    run_ids = list(session.scalars(select(InvestigationRunRow.id).where(InvestigationRunRow.case_id.in_(case_ids))))
    if run_ids:
        session.execute(delete(ToolCallRow).where(ToolCallRow.run_id.in_(run_ids)))
        session.execute(delete(InvestigationResultRow).where(InvestigationResultRow.run_id.in_(run_ids)))
        session.execute(delete(ReviewRow).where(ReviewRow.run_id.in_(run_ids)))
        session.execute(delete(InvestigationRunRow).where(InvestigationRunRow.id.in_(run_ids)))
    session.execute(delete(CaseRow).where(CaseRow.dataset_id == dataset_id))
    return len(case_ids)


def close_cases_except(session: Session, dataset_id: str, keep_ids: set[str]) -> None:
    """Close rows the live engine no longer holds (they left the retention window)."""
    now = _utcnow()
    rows = session.scalars(
        select(CaseRow).where(CaseRow.dataset_id == dataset_id, CaseRow.status != "closed")
    ).all()
    for row in rows:
        if row.id not in keep_ids:
            row.status = "closed"
            row.updated_at = now


def list_cases(
    session: Session,
    *,
    limit: int = 50,
    dataset_id: str | None = None,
    dataset_ids: list[str] | None = None,
    status: str | None = None,
) -> list[CaseRow]:
    stmt = (
        select(CaseRow)
        .options(selectinload(CaseRow.runs).selectinload(InvestigationRunRow.result))
        .options(selectinload(CaseRow.runs).selectinload(InvestigationRunRow.review))
        .order_by(CaseRow.updated_at.desc())
        .limit(limit)
    )
    if dataset_ids is not None:
        if not dataset_ids:
            return []
        stmt = stmt.where(CaseRow.dataset_id.in_(dataset_ids))
    elif dataset_id is not None:
        stmt = stmt.where(CaseRow.dataset_id == dataset_id)
    if status is not None:
        stmt = stmt.where(CaseRow.status == status)
    return list(session.scalars(stmt).all())


def get_case(session: Session, case_id: str) -> CaseRow | None:
    stmt = (
        select(CaseRow)
        .where(CaseRow.id == case_id)
        .options(selectinload(CaseRow.runs).selectinload(InvestigationRunRow.tool_calls))
        .options(selectinload(CaseRow.runs).selectinload(InvestigationRunRow.result))
        .options(selectinload(CaseRow.runs).selectinload(InvestigationRunRow.review))
    )
    return session.scalar(stmt)


def get_run(session: Session, run_id: str) -> InvestigationRunRow | None:
    stmt = (
        select(InvestigationRunRow)
        .where(InvestigationRunRow.id == run_id)
        .options(selectinload(InvestigationRunRow.tool_calls))
        .options(selectinload(InvestigationRunRow.result))
        .options(selectinload(InvestigationRunRow.review))
    )
    return session.scalar(stmt)


def events_for_case(session: Session, case: CaseRow) -> list[EventRow]:
    if not case.event_ids_json:
        return []
    stmt = (
        select(EventRow)
        .where(EventRow.dataset_id == case.dataset_id, EventRow.event_id.in_(list(case.event_ids_json)))
        .order_by(EventRow.timestamp_utc.asc())
    )
    return list(session.scalars(stmt).all())


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def load_auth_events(session: Session, dataset_id: str) -> tuple[AuthEvent, ...]:
    from login_anomaly.events import Outcome

    rows = session.scalars(
        select(EventRow).where(EventRow.dataset_id == dataset_id).order_by(EventRow.timestamp_utc.asc())
    ).all()
    return tuple(
        AuthEvent(
            event_id=row.event_id,
            timestamp_utc=_as_utc(row.timestamp_utc),
            account_id=row.account_id,
            source_ip=row.source_ip,
            outcome=Outcome(row.outcome),
            country_code=row.country_code,
        )
        for row in rows
    )


def result_to_domain(result_row: InvestigationResultRow) -> InvestigationResult:
    from login_anomaly.agentic.contracts import EvidenceReference, ToolCallRecord

    evidence = tuple(
        EvidenceReference(item["event_id"], item["field"], item["summary"]) for item in result_row.evidence_json
    )
    return InvestigationResult(
        alert_id=result_row.run_id,
        verdict=result_row.verdict,
        confidence=result_row.confidence,
        evidence=evidence,
        tool_calls=tuple(
            ToolCallRecord(call.tool_name, call.arguments_json, call.status) for call in result_row.run.tool_calls
        ),
        justification=result_row.justification,
        limitations=tuple(result_row.limitations_json),
    )
