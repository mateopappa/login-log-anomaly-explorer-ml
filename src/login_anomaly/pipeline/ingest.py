"""Turn one finished site publish into cases on the SOC queue.

The worker calls this when a site starts its next publish. Detectors see only
the namespaced events. Labels stay out of this module; the dataset config keeps
the seed and plan so evaluation can rebuild them later.
"""

from __future__ import annotations

from dataclasses import asdict

from sqlalchemy.orm import Session

from login_anomaly.config import CONFIG_VERSION
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.repositories import _jsonable
from login_anomaly.pipeline.envelope import StreamEnvelope
from login_anomaly.pipeline.synthesize import SITE_PLAN, SITE_START
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset
from login_anomaly.simulation.manifest import build_manifest
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow

MODEL_RUN_ID = "site-rf-baseline"


def persist_site_envelopes(session: Session, envelopes: list[StreamEnvelope], model: object) -> dict[str, object]:
    """Run rules, ML, correlation, and the mock investigator. Persist the cases."""
    if not envelopes:
        raise ValueError("empty site batch")
    tenant_ids = {item.tenant_id for item in envelopes}
    if len(tenant_ids) != 1:
        raise ValueError("a site batch is one tenant")
    first = envelopes[0]
    if first.seed is None or first.n_events is None or first.n_accounts is None or first.duration_hours is None:
        raise ValueError("site batch is missing generator provenance")
    config = GeneratorConfig(
        seed=first.seed,
        start_utc=SITE_START,
        duration_hours=first.duration_hours,
        n_accounts=first.n_accounts,
        n_events=first.n_events,
    )
    manifest = build_manifest(config, SITE_PLAN)
    dataset = EventDataset(tuple(item.event for item in envelopes), manifest)
    workflow = run_detection_workflow(dataset, model, ModelRunMetadata(MODEL_RUN_ID))
    stored = {
        "source": "site",
        "tenant_id": first.tenant_id,
        "display_name": first.display_name,
        "region": first.region,
        "generator": asdict(config),
        "plan": asdict(SITE_PLAN),
        "model_run_id": MODEL_RUN_ID,
    }
    repo.upsert_dataset(session, workflow.dataset_id, config.seed, _jsonable(stored))
    repo.insert_events(session, workflow.dataset_id, dataset.events)
    for case in workflow.cases:
        repo.upsert_case(session, case, status="open")
    for run in workflow.case_investigations:
        key = f"site-{workflow.dataset_id}-{run.case.case_id}"
        if repo.find_run_by_idempotency(session, key) is not None:
            continue
        review = next(item for item in workflow.case_reviews if item.case_id == run.case.case_id)
        row = repo.create_run(
            session,
            case_id=run.case.case_id,
            mode=run.mode,
            provider_id=run.provider_id,
            model=None,
            config_version=CONFIG_VERSION,
            idempotency_key=key,
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
    session.flush()
    return {
        "dataset_id": workflow.dataset_id,
        "tenant_id": first.tenant_id,
        "events": len(dataset.events),
        "cases": len(workflow.cases),
    }


def _risk_for(verdict: str) -> str:
    if verdict == "malicious":
        return "high"
    if verdict == "benign":
        return "low"
    return "medium"
