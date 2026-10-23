"""Start and load investigation runs with persistence and provider selection."""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

from sqlalchemy.orm import Session

from login_anomaly.agentic.case_investigator import run_case_investigation
from login_anomaly.agentic.cases import case_input_for
from login_anomaly.agentic.haiku_provider import HaikuInvestigatorProvider
from login_anomaly.agentic.reviewer import review_case_investigation
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.models import InvestigationRunRow
from login_anomaly.services.app_state import AppState
from login_anomaly.services.bootstrap import case_from_row_signals, _risk_for
from login_anomaly.services.providers import resolve_provider


class InvestigationServiceError(Exception):
    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def start_investigation(
    session: Session,
    state: AppState,
    case_id: str,
    *,
    provider_name: str | None = None,
    idempotency_key: str | None = None,
) -> InvestigationRunRow:
    if idempotency_key:
        existing = repo.find_run_by_idempotency(session, idempotency_key)
        if existing is not None:
            return existing

    case_row = repo.get_case(session, case_id)
    if case_row is None:
        raise InvestigationServiceError("case not found", status_code=404)

    try:
        provider = resolve_provider(state.settings, provider_name)
    except LookupError as exc:
        raise InvestigationServiceError(str(exc), status_code=503) from exc
    except ValueError as exc:
        raise InvestigationServiceError(str(exc), status_code=400) from exc

    model_name = None
    if isinstance(provider, HaikuInvestigatorProvider):
        model_name = provider.model

    run = repo.create_run(
        session,
        case_id=case_id,
        mode=provider.mode,
        provider_id=provider.provider_id,
        model=model_name,
        config_version=state.settings.config_version,
        idempotency_key=idempotency_key,
    )
    repo.mark_run_running(session, run)
    session.flush()

    events = repo.load_auth_events(session, case_row.dataset_id)
    case = case_from_row_signals(
        case_row.id,
        case_row.dataset_id,
        case_row.case_kind,
        case_row.priority_hint,
        list(case_row.event_ids_json),
        list(case_row.signals_json),
        list(case_row.associations_json),
    )
    started = time.perf_counter()
    try:
        investigation = run_case_investigation(events, case_input_for(case, events), provider)
        review = review_case_investigation(investigation)
        latency_ms = int((time.perf_counter() - started) * 1000)
        tokens_in = tokens_out = cost = None
        if isinstance(provider, HaikuInvestigatorProvider):
            tokens_in = provider.usage.tokens_in
            tokens_out = provider.usage.tokens_out
            cost = round(provider.usage.cost_usd_est, 6)
            latency_ms = max(latency_ms, provider.usage.latency_ms)
        risk = investigation.result.risk_level or _risk_for(investigation.result.verdict)
        hypotheses = [asdict(item) for item in investigation.result.hypotheses]
        repo.persist_completed_run(
            session,
            run,
            investigation,
            review,
            latency_ms=latency_ms,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd_est=cost,
            risk_level=risk,
            hypotheses=hypotheses,
        )
        session.flush()
        session.expire(run)
    except InvestigationServiceError:
        raise
    except Exception as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        repo.mark_run_failed(session, run, f"{type(exc).__name__}: {exc}", latency_ms=latency_ms)
        session.flush()
        raise InvestigationServiceError(f"investigation failed: {exc}", status_code=500) from exc

    refreshed = repo.get_run(session, run.id)
    assert refreshed is not None
    return refreshed


def serialize_run(run: InvestigationRunRow) -> dict[str, Any]:
    result = None
    if run.result is not None:
        result = {
            "verdict": run.result.verdict,
            "confidence": run.result.confidence,
            "risk_level": run.result.risk_level,
            "justification": run.result.justification,
            "limitations": run.result.limitations_json,
            "evidence": run.result.evidence_json,
            "hypotheses": run.result.hypotheses_json,
        }
    review = None
    if run.review is not None:
        review = {
            "mode": run.review.mode,
            "quality": run.review.quality,
            **{k: v for k, v in run.review.payload_json.items() if k not in {"case_id", "mode", "quality"}},
        }
    return {
        "run_id": run.id,
        "case_id": run.case_id,
        "status": run.status,
        "mode": run.mode,
        "provider_id": run.provider_id,
        "model": run.model,
        "config_version": run.config_version,
        "steps": run.steps,
        "errors": run.errors_json,
        "latency_ms": run.latency_ms,
        "tokens_in": run.tokens_in,
        "tokens_out": run.tokens_out,
        "cost_usd_est": run.cost_usd_est,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "tool_calls": [
            {
                "seq": call.seq,
                "tool_name": call.tool_name,
                "arguments": call.arguments_json,
                "status": call.status,
            }
            for call in run.tool_calls
        ],
        "result": result,
        "review": review,
    }
