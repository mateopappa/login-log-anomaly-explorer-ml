"""Offline evaluation and fair detector comparison for SOC Live replay simulations.

This module belongs strictly to the evaluation package. It consumes ground truth
only after a replay simulation has completed (or during batch benchmark runs).
The runtime simulation engine never imports this module or ground truth.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from login_anomaly.evaluation.metrics import ConfusionMatrix, confusion, f1, precision, recall
from login_anomaly.live.engine import LiveConfig, SimulationService, SimulationState
from login_anomaly.live.sources import (
    REPLAY_ACCOUNTS,
    REPLAY_EVENTS,
    REPLAY_HOURS,
    REPLAY_SCENARIOS,
    START_UTC,
)
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import GeneratedDataset, generate_with_truth


@dataclass(frozen=True)
class DetectorQualityMetrics:
    enabled: bool
    confusion: ConfusionMatrix | None
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    flagged_events: int


@dataclass(frozen=True)
class CaseQualityMetrics:
    cases_total: int
    correct: int
    incorrect: int
    inconclusive: int
    unsupported_evidence: int
    tool_errors: int


@dataclass(frozen=True)
class LiveEvaluationResult:
    """Offline ground-truth score for a completed replay simulation."""

    simulation_id: str
    scenario: str
    seed: int
    detector_mode: str
    enable_rules: bool
    enable_ml: bool
    total_events: int
    malicious_events: int
    benign_events: int
    rules_metrics: DetectorQualityMetrics
    ml_metrics: DetectorQualityMetrics
    case_quality: CaseQualityMetrics
    operational_counts: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "scenario": self.scenario,
            "seed": self.seed,
            "detector_mode": self.detector_mode,
            "enable_rules": self.enable_rules,
            "enable_ml": self.enable_ml,
            "total_events": self.total_events,
            "malicious_events": self.malicious_events,
            "benign_events": self.benign_events,
            "rules": asdict(self.rules_metrics),
            "ml": asdict(self.ml_metrics),
            "case_quality": asdict(self.case_quality),
            "operational_counts": dict(self.operational_counts),
        }


def _detector_metrics(
    enabled: bool,
    labels: list[int],
    flagged_ids: set[str],
    event_ids: list[str],
) -> DetectorQualityMetrics:
    if not enabled:
        return DetectorQualityMetrics(
            enabled=False,
            confusion=None,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            false_positive_rate=0.0,
            flagged_events=0,
        )
    predicted = [1 if eid in flagged_ids else 0 for eid in event_ids]
    cm = confusion(labels, predicted)
    fpr = cm.fp / (cm.fp + cm.tn) if (cm.fp + cm.tn) else 0.0
    return DetectorQualityMetrics(
        enabled=True,
        confusion=cm,
        precision=round(precision(cm), 4),
        recall=round(recall(cm), 4),
        f1=round(f1(cm), 4),
        false_positive_rate=round(fpr, 4),
        flagged_events=cm.tp + cm.fp,
    )


def evaluate_live_replay(service: SimulationService) -> LiveEvaluationResult:
    """Evaluate a finished replay simulation against ground truth offline.

    Raises ValueError if the service did not run in replay mode.
    """
    if service.config.mode != "replay":
        raise ValueError("Only replay simulations can be evaluated against static ground truth.")

    scenario = service.config.scenario
    seed = service.config.seed
    plan = REPLAY_SCENARIOS[scenario]
    config = GeneratorConfig(
        seed=seed,
        start_utc=START_UTC,
        duration_hours=REPLAY_HOURS,
        n_accounts=REPLAY_ACCOUNTS,
        n_events=REPLAY_EVENTS,
    )
    truth_dataset: GeneratedDataset = generate_with_truth(config, plan)
    events = truth_dataset.events
    truth = truth_dataset.ground_truth
    event_ids = [e.event_id for e in events]
    labels = [1 if truth.label_for(eid).is_malicious else 0 for eid in event_ids]

    rule_event_ids: set[str] = set()
    if service.config.enable_rules:
        for incident in service._incidents.values():
            rule_event_ids.update(incident.event_ids)

    ml_event_ids: set[str] = set()
    if service.config.enable_ml:
        ml_event_ids.update(service._ml_signals.keys())

    rules_metrics = _detector_metrics(service.config.enable_rules, labels, rule_event_ids, event_ids)
    ml_metrics = _detector_metrics(service.config.enable_ml, labels, ml_event_ids, event_ids)

    case_records = list(service._cases.values())
    case_correct = case_incorrect = case_inconclusive = unsupported = tool_errors = 0
    for record in case_records:
        if record.run is None:
            continue
        expected_malicious = any(truth.label_for(eid).is_malicious for eid in record.case.event_ids)
        verdict = record.run.result.verdict
        if verdict == "inconclusive":
            case_inconclusive += 1
        elif (verdict == "malicious") == expected_malicious:
            case_correct += 1
        else:
            case_incorrect += 1
        unsupported += sum(item.event_id not in record.case.event_ids for item in record.run.result.evidence)
        tool_errors += sum(call.status != "ok" for call in record.run.result.tool_calls)

    case_quality = CaseQualityMetrics(
        cases_total=len(case_records),
        correct=case_correct,
        incorrect=case_incorrect,
        inconclusive=case_inconclusive,
        unsupported_evidence=unsupported,
        tool_errors=tool_errors,
    )

    summary = service.summary()
    op_counts = {
        "generated": summary["generated"],
        "released": summary["released"],
        "processed": summary["processed"],
        "rule_alerts": summary["rule_alerts"],
        "ml_positive_events": summary["ml_positive_events"],
        "cases_total": summary["cases_total"],
        "cases_open": summary["cases_open"],
        "investigations_completed": summary["investigations_completed"],
        "latency_ms_total": summary["latency_ms_total"],
    }

    return LiveEvaluationResult(
        simulation_id=service.simulation_id,
        scenario=scenario,
        seed=seed,
        detector_mode=summary["detector_mode"],
        enable_rules=service.config.enable_rules,
        enable_ml=service.config.enable_ml,
        total_events=len(events),
        malicious_events=sum(labels),
        benign_events=len(events) - sum(labels),
        rules_metrics=rules_metrics,
        ml_metrics=ml_metrics,
        case_quality=case_quality,
        operational_counts=op_counts,
    )


def compare_replay_detector_configurations(
    scenario: str,
    seed: int,
    model: object,
) -> list[LiveEvaluationResult]:
    """Execute and compare all 4 detector configurations on the exact same replay stream.

    Configurations:
      1. Rules + ML
      2. Rules only
      3. ML only
      4. Ingestion baseline (neither detector enabled)

    Returns 4 evaluated records with identical underlying input datasets.
    """
    configs = [
        ("rules_and_ml", True, True),
        ("rules_only", True, False),
        ("ml_only", False, True),
        ("none", False, False),
    ]

    results: list[LiveEvaluationResult] = []
    for _mode_name, enable_rules, enable_ml in configs:
        fake_clock_now = 0.0

        def clock() -> float:
            return fake_clock_now

        cfg = LiveConfig(
            mode="replay",
            seed=seed,
            scenario=scenario,
            enable_rules=enable_rules,
            enable_ml=enable_ml,
        )
        service = SimulationService(cfg, model, clock=clock)
        service.start()
        # Advance through all events to completion
        while service.state is SimulationState.RUNNING:
            fake_clock_now += 1.0
            service.advance()

        results.append(evaluate_live_replay(service))

    return results
