"""Score one persisted case investigation against rebuilt ground truth.

Ground truth is regenerated from the dataset seed/config — never stored in the
runtime DB path. Callers must live in the API evaluation surface, not detectors.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from login_anomaly.agentic.contracts import (
    EvidenceReference,
    InvestigationInput,
    InvestigationResult,
    ToolCallRecord,
)
from login_anomaly.evaluation.agentic import AlertReference, evaluate_investigation
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate_with_truth
from login_anomaly.simulation.ground_truth import GroundTruth
from login_anomaly.simulation.scenarios import ScenarioPlan


class CaseScoreError(ValueError):
    """Case cannot be scored offline (missing run, unsupported dataset, etc.)."""


def rebuild_ground_truth(seed: int, config: dict[str, Any]) -> GroundTruth:
    """Regenerate labels from the same seed/plan used to produce the dataset."""
    if "generator" in config and "plan" in config:
        generator = config["generator"]
        plan_raw = config["plan"]
        start = generator["start_utc"]
        if isinstance(start, str):
            start_utc = datetime.fromisoformat(start.replace("Z", "+00:00"))
        else:
            raise CaseScoreError("generator.start_utc must be an ISO timestamp")
        gen_config = GeneratorConfig(
            seed=int(generator.get("seed", seed)),
            start_utc=start_utc,
            duration_hours=int(generator["duration_hours"]),
            n_accounts=int(generator["n_accounts"]),
            n_events=int(generator["n_events"]),
        )
        plan = ScenarioPlan(
            bruteforce_campaigns=int(plan_raw.get("bruteforce_campaigns", 0)),
            password_spraying_campaigns=int(plan_raw.get("password_spraying_campaigns", 0)),
            impossible_travel_campaigns=int(plan_raw.get("impossible_travel_campaigns", 0)),
            benign_travelers=int(plan_raw.get("benign_travelers", 0)),
        )
        return generate_with_truth(gen_config, plan).ground_truth

    if config.get("source") == "soc_live":
        mode = config.get("mode")
        if mode != "replay":
            raise CaseScoreError("only SOC Live replay cases can be scored offline (not continuous)")
        scenario = str(config.get("scenario") or "Mixed campaigns")
        from login_anomaly.live.sources import REPLAY_ACCOUNTS, REPLAY_EVENTS, REPLAY_HOURS, REPLAY_SCENARIOS, START_UTC

        if scenario not in REPLAY_SCENARIOS:
            raise CaseScoreError(f"unknown live scenario: {scenario}")
        gen_config = GeneratorConfig(
            seed=seed,
            start_utc=START_UTC,
            duration_hours=REPLAY_HOURS,
            n_accounts=REPLAY_ACCOUNTS,
            n_events=REPLAY_EVENTS,
        )
        return generate_with_truth(gen_config, REPLAY_SCENARIOS[scenario]).ground_truth

    raise CaseScoreError("dataset config does not include enough provenance to rebuild ground truth")


def score_case_investigation(
    *,
    case_id: str,
    event_ids: list[str],
    priority_hint: str,
    case_kind: str,
    first_seen: datetime,
    last_seen: datetime,
    verdict: str,
    confidence: float,
    justification: str,
    limitations: list[str],
    evidence: list[dict[str, Any]],
    tool_calls: list[dict[str, Any]],
    seed: int,
    dataset_config: dict[str, Any],
) -> dict[str, Any]:
    """Return a structured offline score for one case investigation run."""
    truth = rebuild_ground_truth(seed, dataset_config)
    try:
        malicious_ids = frozenset(eid for eid in event_ids if truth.label_for(eid).is_malicious)
    except KeyError as exc:
        raise CaseScoreError(
            "case event ids are not in the rebuilt ground truth — dataset seed/config mismatch"
        ) from exc

    expected_malicious = bool(malicious_ids)
    expected_verdict = "malicious" if expected_malicious else "benign"

    severity = "high" if priority_hint == "high" else "medium"
    rule_id = "case" if case_kind == "rule_backed" else "ml_only"
    investigation_input = InvestigationInput(
        alert_id=case_id,
        rule_id=rule_id,
        severity=severity,
        event_ids=tuple(event_ids),
        first_seen=first_seen,
        last_seen=last_seen,
    )
    result = InvestigationResult(
        alert_id=case_id,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        evidence=tuple(
            EvidenceReference(str(item["event_id"]), str(item["field"]), str(item["summary"]))
            for item in evidence
        ),
        tool_calls=tuple(
            ToolCallRecord(
                tool_name=str(call["tool_name"]),
                arguments={str(k): str(v) for k, v in dict(call.get("arguments") or {}).items()},
                status=str(call.get("status") or "ok"),
            )
            for call in tool_calls
        ),
        justification=justification,
        limitations=tuple(limitations),
    )
    reference = AlertReference(
        alert_id=case_id,
        is_true_alert=expected_malicious,
        malicious_event_ids=malicious_ids,
    )
    scored = evaluate_investigation(result, reference, investigation_input)

    if verdict == "inconclusive":
        match_label = "inconclusive"
    elif scored.verdict_correct:
        match_label = "correct"
    else:
        match_label = "incorrect"

    return {
        "case_id": case_id,
        "expected_malicious": expected_malicious,
        "expected_verdict": expected_verdict,
        "actual_verdict": verdict,
        "verdict_match": match_label,
        "verdict_correct": scored.verdict_correct,
        "malicious_event_ids": sorted(malicious_ids),
        "malicious_event_count": len(malicious_ids),
        "event_count": len(event_ids),
        "policy": {
            "unsupported_evidence": scored.unsupported_evidence,
            "irrelevant_evidence": scored.irrelevant_evidence,
            "forbidden_access_attempts": scored.forbidden_access_attempts,
            "tool_limit_violations": scored.tool_limit_violations,
            "failed_tool_calls": scored.failed_tool_calls,
            "steps": scored.steps,
            "findings": list(scored.findings),
        },
        "note": "Ground truth rebuilt offline from dataset seed/config; never exposed to the investigator.",
    }
