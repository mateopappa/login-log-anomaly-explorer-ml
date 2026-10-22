"""Focused tests for the label-free detector workflow spine."""

import ast
from datetime import datetime, timezone
from pathlib import Path

from login_anomaly.correlation import dataset_id_for
from login_anomaly.ml.features import feature_matrix
from login_anomaly.ml.model import DECISION_THRESHOLD, train_model
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset, generate
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow

UTC = timezone.utc


def config(seed: int = 41) -> GeneratorConfig:
    return GeneratorConfig(seed=seed, start_utc=datetime(2026, 1, 1, tzinfo=UTC), duration_hours=72, n_accounts=50, n_events=800)


def attack_dataset() -> EventDataset:
    return generate(
        config(),
        ScenarioPlan(bruteforce_campaigns=1, password_spraying_campaigns=1, impossible_travel_campaigns=1),
    )


def positive_model(dataset: EventDataset):  # type: ignore[no-untyped-def]
    _, rows = feature_matrix(dataset.events)
    return train_model(rows, [1] * len(rows), seed=7)


class NoPositiveModel:
    """Minimal fitted-model-shaped double with no scores at the fixed threshold."""

    classes_ = (0, 1)

    def predict_proba(self, features):  # type: ignore[no-untyped-def]
        class ProbabilityRows:
            def __init__(self, size: int) -> None:
                self.size = size

            def __getitem__(self, key):  # type: ignore[no-untyped-def]
                assert key == (slice(None), 1)
                return [0.0] * self.size

        return ProbabilityRows(len(features))


def test_workflow_runs_existing_detectors_and_rule_investigator() -> None:
    dataset = attack_dataset()
    result = run_detection_workflow(dataset, positive_model(dataset), ModelRunMetadata("baseline-rf-run-1"))

    assert result.manifest == dataset.manifest
    assert result.dataset_id == dataset_id_for(dataset.manifest)
    assert result.event_ids == tuple(event.event_id for event in dataset.events)
    assert result.rule_alerts
    assert len(result.investigations) == len(result.rule_alerts)
    assert {item.alert_id for item in result.investigations} == {alert.alert_id for alert in result.rule_alerts}
    assert result.ml_positive_signals
    assert {signal.event_id for signal in result.ml_positive_signals} == {event.event_id for event in dataset.events}
    assert all(signal.dataset_id == result.dataset_id for signal in result.ml_positive_signals)
    assert all(signal.model_run_id == "baseline-rf-run-1" for signal in result.ml_positive_signals)
    assert result.model_run.decision_threshold == DECISION_THRESHOLD


def test_workflow_output_is_deterministic_for_identical_inputs() -> None:
    dataset = attack_dataset()
    model = positive_model(dataset)
    model_run = ModelRunMetadata("baseline-rf-run-1")
    assert run_detection_workflow(dataset, model, model_run) == run_detection_workflow(dataset, model, model_run)


def test_workflow_preserves_empty_alert_and_ml_positive_outputs() -> None:
    dataset = generate(config(), ScenarioPlan())
    result = run_detection_workflow(dataset, NoPositiveModel(), ModelRunMetadata("baseline-rf-run-1"))  # type: ignore[arg-type]
    assert result.rule_alerts == ()
    assert result.ml_positive_signals == ()
    assert result.investigations == ()


def test_ml_only_signal_becomes_a_distinct_case_and_mock_investigation() -> None:
    dataset = generate(config(), ScenarioPlan())
    result = run_detection_workflow(dataset, positive_model(dataset), ModelRunMetadata("baseline-rf-run-1"))
    assert result.rule_alerts == ()
    assert result.cases and all(case.case_kind == "ml_only" for case in result.cases)
    assert len(result.case_investigations) == len(result.cases)
    assert all(run.case.case_kind == "ml_only" and run.result.verdict == "inconclusive" for run in result.case_investigations)


def test_ml_signals_have_dataset_provenance_from_the_input_manifest() -> None:
    first, second = attack_dataset(), generate(config(seed=42), ScenarioPlan(bruteforce_campaigns=1))
    first_result = run_detection_workflow(first, positive_model(first), ModelRunMetadata("baseline-rf-run-1"))
    second_result = run_detection_workflow(second, positive_model(second), ModelRunMetadata("baseline-rf-run-1"))
    assert first_result.dataset_id != second_result.dataset_id
    assert {signal.dataset_id for signal in first_result.ml_positive_signals} == {first_result.dataset_id}
    assert {signal.dataset_id for signal in second_result.ml_positive_signals} == {second_result.dataset_id}


def test_workflow_module_imports_no_ground_truth_or_evaluation_apis() -> None:
    import login_anomaly.workflow as workflow

    tree = ast.parse(Path(workflow.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert not any(name.startswith(("login_anomaly.evaluation", "login_anomaly.simulation.ground_truth")) for name in imported)
    assert "login_anomaly.simulation.generator.generate_with_truth" not in imported
