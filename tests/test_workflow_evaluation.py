"""Evaluation-only integration tests for the label-free workflow spine."""

import ast
from pathlib import Path

import pytest

from login_anomaly.evaluation import workflow as workflow_evaluation_module
from login_anomaly.evaluation.experiment import MODEL_RUN_ID, PLAN, dataset_config, train_baseline
from login_anomaly.evaluation.workflow import evaluate_workflow
from login_anomaly.simulation.generator import EventDataset, generate_with_truth
from login_anomaly.workflow import ModelRunMetadata, run_detection_workflow


@pytest.fixture(scope="module")
def model():  # type: ignore[no-untyped-def]
    return train_baseline()[0]


@pytest.fixture(scope="module")
def evaluated(model):  # type: ignore[no-untyped-def]
    generated = generate_with_truth(dataset_config(201), PLAN)
    runtime = run_detection_workflow(EventDataset(generated.events, generated.manifest), model, ModelRunMetadata(MODEL_RUN_ID))
    return runtime, generated.ground_truth


def test_workflow_evaluation_separates_detector_and_investigation_metrics(evaluated) -> None:  # type: ignore[no-untyped-def]
    runtime, truth = evaluated
    result = evaluate_workflow(runtime, truth)
    assert sum(result.rules.__dict__.values()) == len(runtime.event_ids)
    assert sum(result.ml.__dict__.values()) == len(runtime.event_ids)
    assert result.investigation.alerts == len(runtime.rule_alerts)
    assert result.investigation.investigated + result.investigation.failed == result.investigation.alerts
    assert result.case_investigation.cases == len(runtime.cases)
    assert result.case_investigation.correct + result.case_investigation.incorrect + result.case_investigation.inconclusive == len(runtime.cases)


def test_workflow_evaluation_is_reproducible_and_does_not_change_runtime_result(evaluated) -> None:  # type: ignore[no-untyped-def]
    runtime, truth = evaluated
    before = runtime
    assert evaluate_workflow(runtime, truth) == evaluate_workflow(runtime, truth)
    assert runtime == before


def test_truth_is_imported_only_by_the_evaluation_adapter() -> None:
    import login_anomaly.workflow as runtime_module

    def imports(module) -> set[str]:  # type: ignore[no-untyped-def]
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        return {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}

    assert "login_anomaly.simulation.ground_truth" in imports(workflow_evaluation_module)
    assert "login_anomaly.simulation.ground_truth" not in imports(runtime_module)
