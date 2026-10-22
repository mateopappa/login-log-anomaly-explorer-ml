"""Threat Lab: spec validation, reproducibility, compatibility with the generator, and separation of roles."""

import ast
import dataclasses
from pathlib import Path

import pytest

from login_anomaly.detection import rules as rules_module
from login_anomaly.evaluation import experiment
from login_anomaly.evaluation.threat_lab import RESERVED_SEEDS, comparison_rows, run_lab, run_proposal, run_scenario
from login_anomaly.ml.features import feature_matrix
from login_anomaly.ml.model import predict_malicious
from login_anomaly.simulation.generator import generate
from login_anomaly.simulation.scenarios import DECOY_KINDS, HARD_RANGES, NOMINAL_RANGES, ScenarioPlan
from login_anomaly.threat_lab import specs as specs_module
from login_anomaly.threat_lab.proposals import MockScenarioProvider, ScenarioProposalError
from login_anomaly.threat_lab.specs import (
    BASE_PLAN,
    DEFAULT_SEEDS,
    BoundaryShift,
    BenignBehaviorShift,
    DecoyPressure,
    NominalControl,
    ScenarioSpec,
    build_catalog,
)

ONE_SEED = (1001,)


@pytest.fixture(scope="module")
def model():  # type: ignore[no-untyped-def]
    return experiment.train_baseline()[0]


def spec(**overrides) -> ScenarioSpec:  # type: ignore[no-untyped-def]
    fields = {"scenario_id": "probe", "strategy": "test", "description": "probe", "seeds": ONE_SEED, "plan": BASE_PLAN}
    fields.update(overrides)
    return ScenarioSpec(**fields)


# --- 1. parameter validation ---


@pytest.mark.parametrize(
    "overrides",
    [
        {"scenario_id": "Bad-Id"},
        {"scenario_id": ""},
        {"strategy": " "},
        {"description": ""},
        {"seeds": ()},
        {"seeds": [1001]},
        {"seeds": (1001, 1001)},
        {"seeds": (-1,)},
        {"seeds": (True,)},
        {"plan": ScenarioPlan()},
        {"plan": {"bruteforce_campaigns": 1}},
        {"ranges": {"bruteforce_failures": (1, 2)}},
        {"tags": ("ok", "")},
    ],
    ids=["id-case", "id-empty", "strategy", "description", "no-seeds", "seeds-list", "dup-seeds", "neg-seed", "bool-seed",
         "empty-plan", "plan-dict", "ranges-dict", "empty-tag"],
)
def test_invalid_specs_are_rejected(overrides) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        spec(**overrides)


def test_strategy_parameters_are_validated() -> None:
    with pytest.raises(ValueError):
        DecoyPressure(levels=(4,))  # decoy kinds rotate; only multiples of 3 keep the mix balanced
    with pytest.raises(ValueError):
        DecoyPressure(levels=(3,), decoys_only_level=5)
    with pytest.raises(ValueError):
        BoundaryShift(families=("credential_stuffing",))  # not an attack the generator can produce
    with pytest.raises(ValueError):
        BoundaryShift(families=())


def test_catalog_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError):
        build_catalog((NominalControl(), NominalControl()))


def test_specs_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec().seeds = (1,)  # type: ignore[misc]


# --- 2. reproducibility ---


def test_fingerprint_tracks_only_data_determining_parameters() -> None:
    base = spec()
    assert base.fingerprint() == spec().fingerprint()
    assert base.fingerprint() == spec(description="other words", tags=("x",)).fingerprint()
    assert base.fingerprint() != spec(seeds=(1002,)).fingerprint()
    assert base.fingerprint() != spec(plan=dataclasses.replace(BASE_PLAN, benign_decoys=3)).fingerprint()
    assert base.fingerprint() != spec(ranges=HARD_RANGES).fingerprint()


def test_metadata_is_enough_to_rebuild_the_spec() -> None:
    for original in build_catalog():
        meta = original.metadata()
        rebuilt = ScenarioSpec(
            meta["scenario_id"], meta["strategy"], meta["description"], tuple(meta["seeds"]),
            ScenarioPlan(**meta["plan"]), dataclasses.replace(NOMINAL_RANGES, **{k: tuple(v) if isinstance(v, list) else v for k, v in meta["ranges"].items()}),
            tuple(meta["tags"]),
        )
        assert rebuilt == original and rebuilt.fingerprint() == meta["fingerprint"]


def test_catalog_is_deterministic() -> None:
    assert build_catalog() == build_catalog()
    assert [s.scenario_id for s in build_catalog()] == [
        "nominal_control", "decoy_pressure_3", "decoy_pressure_6", "decoy_pressure_12", "decoys_only_6",
        "boundary_bruteforce", "boundary_password_spraying", "boundary_impossible_travel", "benign_behavior_shift",
    ]


def test_running_a_scenario_twice_gives_identical_results(model) -> None:  # type: ignore[no-untyped-def]
    probe = DecoyPressure(levels=(6,), decoys_only_level=None).scenarios(ONE_SEED)[0]
    assert run_scenario(probe, model) == run_scenario(probe, model)


# --- 3. compatibility with the existing generator, scenarios and experiment ---


def test_base_plan_matches_the_experiment_plan() -> None:
    assert BASE_PLAN == experiment.PLAN


def test_boundary_shift_moves_only_its_family() -> None:
    by_id = {s.scenario_id: s for s in BoundaryShift().scenarios(ONE_SEED)}
    bf = by_id["boundary_bruteforce"]
    assert bf.ranges.bruteforce_failures == HARD_RANGES.bruteforce_failures
    assert bf.ranges.spraying_accounts == NOMINAL_RANGES.spraying_accounts
    assert bf.plan == ScenarioPlan(bruteforce_campaigns=BASE_PLAN.bruteforce_campaigns)
    travel = by_id["boundary_impossible_travel"]
    assert travel.ranges == dataclasses.replace(NOMINAL_RANGES, travel_gap_seconds=HARD_RANGES.travel_gap_seconds)


def test_benign_behavior_shift_changes_benign_traffic_parameters() -> None:
    shift = BenignBehaviorShift().scenarios(ONE_SEED)[0]
    assert shift.plan.benign_travelers > BASE_PLAN.benign_travelers
    assert shift.plan.benign_decoys > 0
    assert "distribution_shift" in shift.tags


def test_every_catalog_spec_is_generatable_with_the_experiment_shape() -> None:
    for item in build_catalog(seeds=ONE_SEED):
        dataset = generate(experiment.dataset_config(item.seeds[0]), item.plan, item.ranges)
        assert len(dataset.events) == experiment.dataset_config(item.seeds[0]).n_events


def test_decoy_levels_cover_every_kind_equally() -> None:
    for item in DecoyPressure().scenarios(ONE_SEED):
        assert item.plan.benign_decoys % len(DECOY_KINDS) == 0


def test_default_seeds_are_not_reserved() -> None:
    assert not RESERVED_SEEDS & set(DEFAULT_SEEDS)


# --- 4. rules versus ML on the same events, with existing metrics ---


def test_lab_compares_rules_and_ml_on_each_scenario(model) -> None:  # type: ignore[no-untyped-def]
    catalog = build_catalog(seeds=ONE_SEED)
    lab = run_lab(catalog, model)
    rows = comparison_rows(lab)
    assert [r["scenario_id"] for r in rows] == [s.scenario_id for s in catalog]
    for item in lab["scenarios"]:
        assert {m["method"] for m in item["methods"]} == {"all_benign", "rules", "ml"}
        assert set(item["investigation"]) >= {"alerts", "investigated", "correct", "incorrect", "inconclusive"}
        assert set(item["case_investigation"]) >= {"cases", "correct", "incorrect", "inconclusive"}
        assert item["scenario"]["fingerprint"] == next(s for s in catalog if s.scenario_id == item["scenario"]["scenario_id"]).fingerprint()
    decoys_only = next(r for r in rows if r["scenario_id"] == "decoys_only_6")
    assert decoys_only["malicious_events"] == 0 and decoys_only["rules_recall"] == 0.0
    assert {"rule_alerts", "investigated", "investigation_correct", "investigation_inconclusive", "cases", "case_agent_inconclusive"} <= set(decoys_only)
    assert lab["limitations"]


def test_reserved_seeds_are_refused(model) -> None:  # type: ignore[no-untyped-def]
    for seed in (experiment.TRAIN_SEEDS[0], experiment.EVAL_SETS[0].seeds[0]):
        with pytest.raises(ValueError, match="reserved"):
            run_scenario(spec(seeds=(seed,)), model)


class HostileProvider:
    mode = "mock"
    provider_id = "hostile-test-provider"

    def propose(self) -> dict[str, object]:
        return {"code": "import os"}


def test_mock_proposal_is_validated_then_run_like_a_catalog_scenario(model) -> None:  # type: ignore[no-untyped-def]
    lab = run_proposal(MockScenarioProvider(), model)
    assert [item["scenario"]["scenario_id"] for item in lab["scenarios"]] == ["mock_benign_shift"]
    assert lab["scenarios"][0]["scenario"]["strategy"] == "agent_proposal"


def test_rejected_proposal_never_reaches_the_runner(model) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ScenarioProposalError):
        run_proposal(HostileProvider(), model)


def test_lab_rejects_duplicate_scenario_ids(model) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        run_lab((spec(), spec()), model)


# --- 5. separation of responsibilities ---


def _imports(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    found = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    return found | {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}


def test_scenario_definitions_touch_no_labels_detectors_models_or_investigator() -> None:
    imported = _imports(specs_module.__file__)
    banned = ("login_anomaly.evaluation", "login_anomaly.detection", "login_anomaly.ml", "login_anomaly.agentic", "login_anomaly.simulation.ground_truth")
    assert not any(name.startswith(banned) for name in imported)
    assert "login_anomaly.simulation.generator" not in imported  # definitions do not generate data


def test_running_the_lab_leaves_detectors_model_and_eval_sets_unchanged(model) -> None:  # type: ignore[no-untyped-def]
    thresholds = {name: getattr(rules_module, name) for name in dir(rules_module) if name.isupper()}
    eval_sets, train_seeds = experiment.EVAL_SETS, experiment.TRAIN_SEEDS
    probe_events = generate(experiment.dataset_config(1002), BASE_PLAN).events
    _, rows = feature_matrix(probe_events)
    before = predict_malicious(model, rows)

    run_lab(build_catalog(seeds=ONE_SEED), model)

    assert {name: getattr(rules_module, name) for name in dir(rules_module) if name.isupper()} == thresholds
    assert experiment.EVAL_SETS == eval_sets and experiment.TRAIN_SEEDS == train_seeds
    assert feature_matrix(probe_events)[1] == rows
    assert predict_malicious(model, rows) == before
