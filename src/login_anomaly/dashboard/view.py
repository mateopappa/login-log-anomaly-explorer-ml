"""Dashboard logic without Streamlit. The app renders what this module computes, and these functions are tested.

Detection runs on ``EventDataset`` (events only). Comparison with ground truth runs on
``GeneratedDataset``, and only in the evaluation panel. Both come from the same build,
so their events are identical.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from login_anomaly.agentic.contracts import MAX_STEPS, MAX_TOOL_CALLS, AgentEvaluationResult
from login_anomaly.agentic.investigator import AlertInvestigation, investigate_alerts
from login_anomaly.correlation import MlPositiveSignal, RuleAlertSignal
from login_anomaly.detection.rules import Alert, detect
from login_anomaly.ml.features import feature_matrix
from login_anomaly.live.engine import SimulationService
from login_anomaly.ml.model import predict_malicious
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset, generate
from login_anomaly.simulation.scenarios import NOMINAL_RANGES, ScenarioPlan
from login_anomaly.threat_lab.specs import ScenarioSpec
from login_anomaly.workflow import DetectionWorkflowResult, ModelRunMetadata, run_detection_workflow

# What the demo runs for real and what it does not. Shown in the agentic tab.
COMPONENT_STATUS: tuple[dict[str, str], ...] = (
    {"component": "Synthetic event generator", "status": "Implemented", "note": "Synthetic data only; seeded and reproducible."},
    {"component": "Rule detector", "status": "Implemented", "note": "Its alerts are the investigator's input."},
    {"component": "ML detector", "status": "Implemented", "note": "Event-level signals become provenance-bound cases."},
    {"component": "Investigator (deterministic)", "status": "Implemented", "note": "Rule-based playbooks over read-only tools. No LLM."},
    {"component": "Case Investigator", "status": "Implemented (mock)", "note": "Bounded provider-independent loop; mock mode only, no LLM call."},
    {"component": "Case Reviewer", "status": "Implemented (deterministic)", "note": "Runtime evidence/policy review without labels."},
    {"component": "Offline evaluator", "status": "Implemented", "note": "Uses labels only after runtime work is complete."},
    {"component": "Scenario proposal agent", "status": "Implemented (mock)", "note": "Strict validated ScenarioSpec proposals; no executable code."},
    {"component": "SOC Live simulator", "status": "Implemented", "note": "Replay and continuous modes release events over time; agents are mock."},
)


@dataclass(frozen=True)
class SessionConfig:
    seed: int
    n_events: int
    n_accounts: int
    duration_hours: int
    plan: ScenarioPlan

    def generator_config(self) -> GeneratorConfig:
        return GeneratorConfig(
            seed=self.seed,
            start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_hours=self.duration_hours,
            n_accounts=self.n_accounts,
            n_events=self.n_events,
        )


def events_for(session: SessionConfig) -> EventDataset:
    """What detectors receive: events and manifest only."""
    return generate(session.generator_config(), session.plan)


def rule_alerts(events: EventDataset) -> list[Alert]:
    return detect(list(events.events))


def ml_flags(model: object, events: EventDataset) -> dict[str, int]:
    ids, rows = feature_matrix(events.events)
    return dict(zip(ids, predict_malicious(model, rows)))  # type: ignore[arg-type]


def workflow_for(model: object, events: EventDataset) -> DetectionWorkflowResult:
    """Run the complete label-free SOC workflow for one dashboard dataset."""
    return run_detection_workflow(events, model, ModelRunMetadata("dashboard-rf-baseline"))  # type: ignore[arg-type]


def alert_rows(alerts: list[Alert]) -> list[dict[str, Any]]:
    return [
        {
            "alert_id": alert.alert_id,
            "rule": alert.rule_id,
            "severity": alert.severity.value,
            "events": len(alert.event_ids),
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
        }
        for alert in alerts
    ]


def explain_alert(alert: Alert) -> dict[str, Any]:
    """Why an alert fired: rule, threshold, evidence, and the event ids it is based on."""
    return {
        "alert_id": alert.alert_id,
        "rule": alert.rule_id,
        "severity": alert.severity.value,
        "explanation": alert.explanation,
        "evidence": list(alert.evidence),
        "event_ids": list(alert.event_ids),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
    }


def related_events(events: EventDataset, alert: Alert) -> list[dict[str, Any]]:
    wanted = set(alert.event_ids)
    return [
        {
            "event_id": event.event_id,
            "timestamp_utc": event.timestamp_utc.isoformat(),
            "account_id": event.account_id,
            "source_ip": event.source_ip,
            "outcome": event.outcome.value,
            "country_code": event.country_code,
        }
        for event in events.events
        if event.event_id in wanted
    ]


# --- investigation (rule alerts only) ---


def investigations_for(events: EventDataset, alerts: list[Alert]) -> tuple[AlertInvestigation, ...]:
    """Run the existing investigator on the rule alerts. It receives observable events only."""
    return investigate_alerts(events.events, alerts)


def case_rows(workflow: DetectionWorkflowResult) -> list[dict[str, Any]]:
    reviews = {review.case_id: review for review in workflow.case_reviews}
    runs = {run.case.case_id: run for run in workflow.case_investigations}
    return [
        {
            "case_id": case.case_id,
            "kind": case.case_kind,
            "events": len(case.event_ids),
            "signals": len(case.signals),
            "priority": case.priority_hint,
            "mode": runs[case.case_id].mode,
            "verdict": runs[case.case_id].result.verdict,
            "review": reviews[case.case_id].quality,
        }
        for case in workflow.cases
    ]


def case_detail(workflow: DetectionWorkflowResult, case_id: str) -> dict[str, Any]:
    run = next(run for run in workflow.case_investigations if run.case.case_id == case_id)
    review = next(review for review in workflow.case_reviews if review.case_id == case_id)
    return {
        "case_id": run.case.case_id,
        "kind": run.case.case_kind,
        "dataset_id": run.case.dataset_id,
        "event_ids": list(run.case.event_ids),
        "mode": run.mode,
        "provider": run.provider_id,
        "verdict": run.result.verdict,
        "confidence": run.result.confidence,
        "justification": run.result.justification,
        "evidence": [asdict(item) for item in run.result.evidence],
        "tool_calls": [asdict(item) for item in run.result.tool_calls],
        "errors": list(run.errors),
        "review": asdict(review),
    }

def live_case_rows(service: SimulationService) -> list[dict[str, Any]]:
    """Clean, scannable case overview rows for SOC Live triage."""
    rows = []
    for case in service.cases():
        rows.append(
            {
                "Case ID": case["case_id"],
                "Kind": "Rule-backed" if case["kind"] == "rule_backed" else "ML-only",
                "Priority": case["priority"].replace("_", " ").upper(),
                "Signals": case["signals"],
                "Events": case["events"],
                "Verdict": case["verdict"].upper() if case["verdict"] != "not investigated" else "Capped (ML budget)",
                "Review": case["review"],
                "Status": case["status"],
            }
        )
    return rows


def live_case_detail(service: SimulationService, case_id: str) -> dict[str, Any] | None:
    """Selected SOC Live case: the events it was built from, plus its investigation and review if run."""
    record = service.case_record(case_id)
    if record is None:
        return None

    signals_detail = []
    for signal in record.case.signals:
        if isinstance(signal, RuleAlertSignal):
            signals_detail.append(
                {
                    "signal_id": signal.signal_id,
                    "source": "Rule detector",
                    "rule_id": signal.rule_id,
                    "alert_id": signal.alert_id,
                    "severity": signal.severity,
                    "explanation": signal.explanation,
                    "evidence": list(signal.evidence),
                    "event_ids": list(signal.event_ids),
                }
            )
        elif isinstance(signal, MlPositiveSignal):
            signals_detail.append(
                {
                    "signal_id": signal.signal_id,
                    "source": "ML detector (RF)",
                    "rule_id": "—",
                    "alert_id": "—",
                    "severity": "medium",
                    "explanation": f"ML anomaly flagged (prob >= {signal.threshold:g})",
                    "score": signal.score,
                    "threshold": signal.threshold,
                    "event_ids": [signal.event_id],
                }
            )

    associations = [
        {
            "ml_signal_id": a.ml_signal_id,
            "rule_signal_id": a.rule_signal_id,
            "event_id": a.event_id,
            "basis": a.basis,
            "candidate_rule_signal_ids": list(a.candidate_rule_signal_ids),
        }
        for a in record.case.associations
    ]

    in_window = case_id in getattr(service, "_active_case_ids", set())

    detail: dict[str, Any] = {
        "case_id": case_id,
        "kind": record.case.case_kind,
        "priority": record.case.priority_hint,
        "signals": len(record.case.signals),
        "signals_detail": signals_detail,
        "associations": associations,
        "in_window": in_window,
        "events": list(record.events),
    }
    if record.run is None or record.review is None:
        detail["note"] = "Not investigated. The analyst starts it from the dossier."
        return detail
    run, review = record.run, record.review
    detail.update(
        {
            "mode": run.mode,
            "provider": run.provider_id,
            "verdict": run.result.verdict,
            "confidence": run.result.confidence,
            "justification": run.result.justification,
            "evidence": [asdict(item) for item in run.result.evidence],
            "tool_calls": [asdict(item) for item in run.result.tool_calls],
            "uncertainty": list(review.uncertainty),
            "errors": list(run.errors),
            "review": asdict(review),
        }
    )
    return detail


def _correctness(evaluation: AgentEvaluationResult | None) -> str:
    if evaluation is None:
        return "not scored"
    return {True: "correct", False: "incorrect", None: "inconclusive"}[evaluation.verdict_correct]


def _limit_reached(item: AlertInvestigation) -> bool:
    return item.run is not None and bool(item.run.refused_tools)


def investigation_summary(
    investigations: tuple[AlertInvestigation, ...], evaluations: dict[str, AgentEvaluationResult] | None = None
) -> dict[str, Any]:
    done = [item for item in investigations if item.run is not None]
    verdicts = Counter(item.run.result.verdict for item in done)  # type: ignore[union-attr]
    summary: dict[str, Any] = {
        "alerts": len(investigations),
        "investigated": len(done),
        "failed": len(investigations) - len(done),
        "malicious": verdicts["malicious"],
        "benign": verdicts["benign"],
        "inconclusive": verdicts["inconclusive"],
        "limit_reached": sum(_limit_reached(item) for item in investigations),
        "tool_errors": sum(len(item.run.failed_tools) for item in done if item.run is not None),
    }
    if evaluations is not None:
        scored = [evaluations[item.alert_id] for item in done if item.alert_id in evaluations]
        outcome = Counter(_correctness(e) for e in scored)
        summary["evaluation"] = {
            "scored": len(scored),
            "correct": outcome["correct"],
            "incorrect": outcome["incorrect"],
            "inconclusive": outcome["inconclusive"],
            "unsupported_evidence": sum(e.unsupported_evidence for e in scored),
            "forbidden_access_attempts": sum(e.forbidden_access_attempts for e in scored),
            "tool_limit_violations": sum(e.tool_limit_violations for e in scored),
        }
    return summary


def investigation_rows(
    investigations: tuple[AlertInvestigation, ...], evaluations: dict[str, AgentEvaluationResult] | None = None
) -> list[dict[str, Any]]:
    rows = []
    for item in investigations:
        run = item.run
        row: dict[str, Any] = {
            "alert_id": item.alert_id,
            "rule": item.rule_id,
            "status": "failed" if run is None else ("limit reached" if run.refused_tools else "completed"),
            "verdict": None if run is None else run.result.verdict,
            "confidence": None if run is None else run.result.confidence,
            "tool_calls": None if run is None else len(run.result.tool_calls),
            "steps": None if run is None else run.steps,
            "evidence": None if run is None else len(run.result.evidence),
        }
        if evaluations is not None:
            row["evaluation"] = _correctness(evaluations.get(item.alert_id))
        rows.append(row)
    return rows


def investigation_detail(item: AlertInvestigation, evaluation: AgentEvaluationResult | None = None) -> dict[str, Any]:
    """Everything shown for one selected alert. ``evaluation`` is None when not scored."""
    run = item.run
    if run is None:
        return {"alert_id": item.alert_id, "rule": item.rule_id, "status": "failed", "error": item.error, "evaluation": None}
    result = run.result
    return {
        "alert_id": item.alert_id,
        "rule": item.rule_id,
        "status": "limit reached" if run.refused_tools else "completed",
        "error": None,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "justification": result.justification,
        "evidence": [asdict(e) for e in result.evidence],
        "tool_calls": [
            {"#": index, "tool": call.tool_name, "status": call.status, "arguments": ", ".join(f"{k}={v}" for k, v in call.arguments.items())}
            for index, call in enumerate(result.tool_calls, start=1)
        ],
        "limitations": list(result.limitations),
        "budget": {
            "steps": run.steps,
            "max_steps": MAX_STEPS,
            "tool_calls": len(result.tool_calls),
            "max_tool_calls": MAX_TOOL_CALLS,
            "failed_tools": list(run.failed_tools),
            "refused_tools": list(run.refused_tools),
        },
        "evaluation": None if evaluation is None else {**asdict(evaluation), "findings": list(evaluation.findings)},
    }


# --- threat lab (catalog and per-scenario detail; the lab's labels were used upstream, not here) ---


def catalog_rows(specs: tuple[ScenarioSpec, ...]) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": spec.scenario_id,
            "strategy": spec.strategy,
            "seeds": ", ".join(str(seed) for seed in spec.seeds),
            "campaigns": ", ".join(f"{name}={value}" for name, value in asdict(spec.plan).items() if value),
            "ranges": "nominal" if spec.ranges == NOMINAL_RANGES else "shifted",
            "fingerprint": spec.fingerprint()[:12],
        }
        for spec in specs
    ]


def scenario_detail(item: dict[str, Any]) -> dict[str, Any]:
    """Per-seed F1 and false-positive alerts for one scenario from ``run_lab``."""
    per_seed = [
        {"method": method["method"], "seed": seed, "f1": score}
        for method in item["methods"]
        if method["method"] in ("rules", "ml")
        for seed, score in zip(item["scenario"]["seeds"], method["f1_per_seed"])
    ]
    false_positive_alerts = [
        {"rule / decoy kind": key, "false positive alerts": count}
        for key, count in item["alerts_without_malicious_events_by_rule_and_decoy"].items()
    ]
    return {"per_seed": per_seed, "false_positive_alerts": false_positive_alerts}
