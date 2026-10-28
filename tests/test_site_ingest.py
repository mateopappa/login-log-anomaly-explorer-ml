"""Five site publishes become one SOC queue, and a case can be scored offline."""

from __future__ import annotations

from pathlib import Path

from login_anomaly.evaluation.case_score import score_case_investigation
from login_anomaly.evaluation.experiment import train_baseline
from login_anomaly.persistence import repositories as repo
from login_anomaly.persistence.db import init_db, reset_engine, session_scope
from login_anomaly.pipeline.ingest import persist_site_envelopes
from login_anomaly.pipeline.synthesize import build_tenant_envelopes
from login_anomaly.tenants import TENANTS


def test_five_sites_share_one_queue_and_a_case_scores(tmp_path: Path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'sites.db'}"
    reset_engine()
    init_db(url)
    model = train_baseline()[0]
    try:
        with session_scope(url) as session:
            for tenant in TENANTS:
                envelopes = build_tenant_envelopes(tenant, base_seed=42, n_events=80, n_accounts=30)
                persist_site_envelopes(session, envelopes, model)

        with session_scope(url) as session:
            sites = repo.site_datasets(session)
            assert {str(row.config_json["tenant_id"]) for row in sites} == {tenant.tenant_id for tenant in TENANTS}
            cases = repo.list_cases(session, dataset_ids=[row.id for row in sites], limit=200)
            assert cases
            assert {case.dataset_id for case in cases} <= {row.id for row in sites}
            case = next(item for item in cases if item.runs and item.runs[-1].result)
            dataset = next(row for row in sites if row.id == case.dataset_id)
            run = case.runs[-1]
            assert run.result is not None
            scored = score_case_investigation(
                case_id=case.id,
                event_ids=list(run.event_ids_json or []),
                priority_hint=case.priority_hint,
                case_kind=case.case_kind,
                first_seen=case.updated_at,
                last_seen=case.updated_at,
                verdict=run.result.verdict,
                confidence=run.result.confidence,
                justification=run.result.justification,
                limitations=list(run.result.limitations_json or []),
                evidence=list(run.result.evidence_json or []),
                tool_calls=[],
                seed=dataset.seed,
                dataset_config=dict(dataset.config_json),
            )
            assert scored["verdict_match"] in {"correct", "incorrect", "inconclusive"}
    finally:
        reset_engine()
