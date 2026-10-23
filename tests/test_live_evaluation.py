"""Tests for offline evaluation of live replay runs and fair detector comparison."""

from __future__ import annotations

import pytest

from login_anomaly.evaluation.live import (
    LiveEvaluationResult,
    compare_replay_detector_configurations,
    evaluate_live_replay,
)
from login_anomaly.live.engine import LiveConfig, SimulationService, SimulationState


class FakeModel:
    classes_ = [0, 1]

    def predict_proba(self, rows):  # type: ignore[no-untyped-def]
        import numpy as np

        return np.array([[0.0, 1.0]] * len(rows))


def test_evaluate_live_replay_rejects_continuous_mode() -> None:
    service = SimulationService(LiveConfig("continuous", seed=42), FakeModel())
    with pytest.raises(ValueError, match="Only replay simulations can be evaluated"):
        evaluate_live_replay(service)


def test_evaluate_completed_replay_produces_quality_and_operational_metrics() -> None:
    clock_now = 0.0

    def clock() -> float:
        return clock_now

    service = SimulationService(
        LiveConfig("replay", seed=31, scenario="Mixed campaigns", enable_rules=True, enable_ml=True),
        FakeModel(),
        clock=clock,
    )
    service.start()
    while service.state is SimulationState.RUNNING:
        clock_now += 1.0
        service.advance()

    result = evaluate_live_replay(service)
    assert isinstance(result, LiveEvaluationResult)
    assert result.scenario == "Mixed campaigns"
    assert result.seed == 31
    assert result.detector_mode == "rules_and_ml"
    assert result.total_events == 1500
    assert result.malicious_events > 0
    assert result.benign_events > 0

    assert result.rules_metrics.enabled is True
    assert result.rules_metrics.f1 > 0
    assert result.ml_metrics.enabled is True
    assert result.ml_metrics.flagged_events > 0

    assert result.operational_counts["released"] == 1500
    assert result.operational_counts["processed"] == 1500
    assert result.operational_counts["cases_total"] > 0


def test_compare_replay_detector_configurations_runs_all_four_modes_identically() -> None:
    results = compare_replay_detector_configurations("Mixed campaigns", seed=31, model=FakeModel())
    assert len(results) == 4

    modes = [r.detector_mode for r in results]
    assert modes == ["rules_and_ml", "rules_only", "ml_only", "none"]

    for r in results:
        # Identical underlying event stream
        assert r.total_events == 1500
        assert r.malicious_events == results[0].malicious_events
        assert r.operational_counts["released"] == 1500
        assert r.operational_counts["processed"] == 1500

    rules_and_ml = results[0]
    rules_only = results[1]
    ml_only = results[2]
    none_config = results[3]

    # Rules only has no ML signals
    assert rules_only.ml_metrics.enabled is False
    assert rules_only.operational_counts["ml_positive_events"] == 0
    assert rules_only.rules_metrics.enabled is True

    # ML only has no rule alerts
    assert ml_only.rules_metrics.enabled is False
    assert ml_only.operational_counts["rule_alerts"] == 0
    assert ml_only.ml_metrics.enabled is True

    # Neither detector has 0 flags and 0 cases, serving as the pure ingestion baseline
    assert none_config.rules_metrics.enabled is False
    assert none_config.ml_metrics.enabled is False
    assert none_config.operational_counts["rule_alerts"] == 0
    assert none_config.operational_counts["ml_positive_events"] == 0
    assert none_config.operational_counts["cases_total"] == 0
