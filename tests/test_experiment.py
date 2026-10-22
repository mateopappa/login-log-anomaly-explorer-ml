"""Experiment discipline: seed separation, identical rows across methods, nominal control, reproducibility.

These tests check the experiment's structure and its controls. They do not assert that any
detector performs well on any set. Whether a method is better is a result to report.
"""

import pytest

from login_anomaly.evaluation.experiment import EVAL_SETS, TRAIN_SEEDS, EvalSet, run_experiment
from login_anomaly.simulation.scenarios import HARD_RANGES, NOMINAL_RANGES


@pytest.fixture(scope="module")
def result() -> dict[str, object]:
    return run_experiment()


def _set(result: dict[str, object], name: str) -> dict[str, object]:
    return next(s for s in result["evaluation_sets"] if s["name"] == name)  # type: ignore[union-attr]


def _method(eval_set: dict[str, object], name: str) -> dict[str, object]:
    return next(m for m in eval_set["methods"] if m["method"] == name)  # type: ignore[union-attr]


def test_all_evaluation_seeds_are_disjoint_from_training_and_each_other() -> None:
    seen: set[int] = set(TRAIN_SEEDS)
    for eval_set in EVAL_SETS:
        assert seen.isdisjoint(eval_set.seeds), eval_set.name
        seen |= set(eval_set.seeds)


def test_overlapping_seeds_are_rejected() -> None:
    clash = EvalSet(name="clash", description="x", seeds=(TRAIN_SEEDS[0],), plan=EVAL_SETS[0].plan, ranges=NOMINAL_RANGES)
    with pytest.raises(ValueError, match="overlap"):
        run_experiment(eval_sets=(clash,))


def test_every_set_has_one_row_count_per_method(result: dict[str, object]) -> None:
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        counts = {sum(m["confusion"].values()) for m in eval_set["methods"]}  # type: ignore[index, union-attr]
        assert len(counts) == 1, eval_set["name"]  # type: ignore[index]


def test_trivial_baseline_detects_nothing_in_every_set(result: dict[str, object]) -> None:
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        trivial = _method(eval_set, "all_benign")  # type: ignore[arg-type]
        assert trivial["confusion"]["tp"] == 0  # type: ignore[index]
        assert trivial["recall"] == 0.0


def test_nominal_set_is_kept_as_a_control_with_the_earlier_numbers(result: dict[str, object]) -> None:
    nominal = _set(result, "nominal")
    rules = _method(nominal, "rules")
    ml = _method(nominal, "ml")
    assert (rules["precision"], rules["recall"], rules["f1"]) == (0.9717, 0.9562, 0.9639)  # changed by the traveler-isolation fix, not by decoys
    assert (ml["precision"], ml["recall"], ml["f1"]) == (0.9805, 1.0, 0.9901)


def test_shifted_set_uses_the_non_nominal_ranges(result: dict[str, object]) -> None:
    shifted = _set(result, "boundary_stress_with_decoys")
    assert shifted["ranges_are_nominal"] is False
    assert shifted["ranges"] == {  # type: ignore[index]
        "bruteforce_failures": HARD_RANGES.bruteforce_failures,
        "bruteforce_window_seconds": HARD_RANGES.bruteforce_window_seconds,
        "spraying_accounts": HARD_RANGES.spraying_accounts,
        "spraying_attempts_per_account": HARD_RANGES.spraying_attempts_per_account,
        "spraying_window_seconds": HARD_RANGES.spraying_window_seconds,
        "travel_gap_seconds": HARD_RANGES.travel_gap_seconds,
    }


def test_each_set_reports_the_required_metrics(result: dict[str, object]) -> None:
    required = {"confusion", "precision", "recall", "f1", "f1_per_seed", "f1_min", "f1_max", "recall_by_scenario"}
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        for method in eval_set["methods"]:  # type: ignore[index, union-attr]
            assert required <= set(method)


def test_alerts_without_malicious_events_are_counted_per_rule(result: dict[str, object]) -> None:
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        assert isinstance(eval_set["alerts_without_malicious_events_by_rule_and_decoy"], dict)  # type: ignore[index]


def test_each_evaluation_set_reports_workflow_detector_and_investigation_results_per_seed(result: dict[str, object]) -> None:
    for eval_set in result["evaluation_sets"]:  # type: ignore[union-attr]
        assert set(eval_set["investigation"]) >= {"alerts", "investigated", "correct", "incorrect", "inconclusive"}  # type: ignore[index]
        assert set(eval_set["case_investigation"]) >= {"cases", "correct", "incorrect", "inconclusive"}  # type: ignore[index]
        for dataset in eval_set["datasets"]:  # type: ignore[index]
            workflow = dataset["workflow"]
            assert set(workflow["detectors"]) == {"rules", "ml"}
            assert set(workflow["investigation"]) >= {"alerts", "investigated", "correct", "incorrect", "inconclusive"}
            assert set(workflow["case_investigation"]) >= {"cases", "correct", "incorrect", "inconclusive"}


def test_result_is_reproducible_across_runs(result: dict[str, object]) -> None:
    assert run_experiment() == result


def test_limitations_are_documented(result: dict[str, object]) -> None:
    assert any("Synthetic" in item for item in result["limitations"])  # type: ignore[union-attr]
