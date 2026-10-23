"""Threat Lab HTTP surface. Execution uses evaluation.threat_lab (ground truth allowed there)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from login_anomaly.api.deps import app_state_dep, db_session
from login_anomaly.evaluation.threat_lab import run_lab, run_scenario
from login_anomaly.persistence.models import EvaluationRunRow
from login_anomaly.services.app_state import AppState
from login_anomaly.threat_lab.proposals import MockScenarioProvider, validate_proposal
from login_anomaly.threat_lab.specs import build_catalog

router = APIRouter(prefix="/threat-lab", tags=["threat-lab"])


class ThreatRunRequest(BaseModel):
    scenario_id: str | None = Field(
        default=None,
        description="Catalog scenario id. Omit to run the full catalog (slow).",
    )
    proposal: bool = Field(default=False, description="If true, run one mock scenario proposal instead.")


@router.get("/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": spec.scenario_id,
            "strategy": spec.strategy,
            "description": spec.description,
            "seeds": list(spec.seeds),
            "tags": list(spec.tags),
            "plan": {
                "bruteforce_campaigns": spec.plan.bruteforce_campaigns,
                "password_spraying_campaigns": spec.plan.password_spraying_campaigns,
                "impossible_travel_campaigns": spec.plan.impossible_travel_campaigns,
                "benign_travelers": spec.plan.benign_travelers,
                "benign_decoys": spec.plan.benign_decoys,
            },
        }
        for spec in build_catalog()
    ]


@router.post("/runs")
def run_threat(
    body: ThreatRunRequest,
    session: Session = Depends(db_session),
    state: AppState = Depends(app_state_dep),
) -> dict[str, Any]:
    model = state.ensure_model()
    try:
        if body.proposal:
            spec = validate_proposal(MockScenarioProvider().propose())
            result = {"scenarios": [run_scenario(spec, model)], "limitations": []}
            kind = "threat_lab_proposal"
            config = {"proposal": True, "scenario_id": spec.scenario_id}
        elif body.scenario_id:
            catalog = {spec.scenario_id: spec for spec in build_catalog()}
            if body.scenario_id not in catalog:
                raise HTTPException(status_code=404, detail=f"unknown scenario_id: {body.scenario_id}")
            spec = catalog[body.scenario_id]
            result = {"scenarios": [run_scenario(spec, model)], "limitations": []}
            kind = "threat_lab_scenario"
            config = {"scenario_id": body.scenario_id}
        else:
            result = run_lab(build_catalog(), model)
            kind = "threat_lab_catalog"
            config = {"catalog": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    run_id = f"threat-{uuid.uuid4().hex[:12]}"
    # Compact metrics for storage: per-scenario method F1 + case investigation counts.
    compact = []
    for item in result.get("scenarios", []):
        methods = item.get("methods", [])
        method_rows = methods if isinstance(methods, list) else []
        scenario_meta = item.get("scenario") or {}
        compact.append(
            {
                "scenario_id": scenario_meta.get("scenario_id") or scenario_meta.get("id"),
                "scenario": scenario_meta,
                "methods": [
                    {
                        "method": row.get("method"),
                        "precision": row.get("precision"),
                        "recall": row.get("recall"),
                        "f1": row.get("f1"),
                    }
                    for row in method_rows
                    if isinstance(row, dict)
                ],
                "case_investigation": item.get("case_investigation"),
            }
        )
    session.add(
        EvaluationRunRow(
            id=run_id,
            kind=kind,
            seed=0,
            config_json=config,
            metrics_json={"scenarios": compact, "limitations": result.get("limitations", [])},
            created_at=datetime.now(timezone.utc),
        )
    )
    session.flush()
    return {"evaluation_id": run_id, "kind": kind, "result": {"scenarios": compact, "limitations": result.get("limitations", [])}}
