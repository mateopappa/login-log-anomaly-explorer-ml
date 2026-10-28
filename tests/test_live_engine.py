"""SOC Live engine: released-only visibility, lifecycle, bounded history, deterministic replay.

Time is a fake clock stepped by the test, so nothing sleeps. The models are tiny fakes except
where a test says it uses the real baseline.
"""

import numpy as np
import pytest

from login_anomaly.live import engine as engine_module
from login_anomaly.live.engine import (
    ACTIVITY_FEED,
    EVENT_FEED,
    MAX_BUFFER,
    MAX_HISTORY,
    RETENTION,
    LiveConfig,
    SimulationService,
    SimulationState,
)
from login_anomaly.live.sources import replay_events


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class FlagEverything:
    classes_ = [0, 1]

    def predict_proba(self, rows):  # type: ignore[no-untyped-def]
        return np.array([[0.0, 1.0]] * len(rows))


class FlagNothing:
    classes_ = [0, 1]

    def predict_proba(self, rows):  # type: ignore[no-untyped-def]
        return np.array([[1.0, 0.0]] * len(rows))


def replay(scenario: str = "Mixed campaigns", seed: int = 31, model: object | None = None) -> tuple[SimulationService, FakeClock]:
    clock = FakeClock()
    service = SimulationService(LiveConfig("replay", seed, scenario=scenario), model or FlagNothing(), clock=clock)
    return service, clock


def run_to_end(service: SimulationService, clock: FakeClock, limit: int = 100_000) -> int:
    steps = 0
    while service.state is SimulationState.RUNNING and steps < limit:
        clock.now += 1.0
        service.advance()
        steps += 1
    return steps


# --- configuration ------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "live"},
        {"mode": "replay", "scenario": "No such scenario"},
        {"mode": "replay", "events_per_second": 0},
        {"mode": "replay", "events_per_second": 51},
        {"mode": "replay", "events_per_second": True},
        {"mode": "continuous", "attacks": frozenset({"ground_truth"})},
        {"mode": "continuous", "seed": -1},
    ],
)
def test_invalid_configuration_is_rejected(kwargs) -> None:  # type: ignore[no-untyped-def]
    values = {"seed": 1, **kwargs}
    with pytest.raises(ValueError):
        LiveConfig(**values)


def test_default_rate_is_five_events_per_second() -> None:
    assert LiveConfig("replay", 1).events_per_second == 5.0


# --- replay: timing, visibility, pause, resume, completion ----------------------


def test_replay_releases_at_the_configured_rate_by_simulated_time() -> None:
    service, clock = replay()
    service.start()
    clock.now += 1.0
    assert service.advance() == 5
    clock.now += 1.0
    service.advance()
    assert service.summary()["released"] == 10
    assert service.summary()["effective_rate"] == 5.0


def test_only_released_events_reach_detection_correlation_and_investigation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    service, clock = replay(model=FlagEverything())
    order = [e.event_id for e in replay_events("Mixed campaigns", 31)]
    seen: list[set[str]] = []
    original = engine_module.detect

    def spy(events):  # type: ignore[no-untyped-def]
        ids = {event.event_id for event in events}
        seen.append(ids)
        assert ids <= set(order[: service.released]), "the detector saw an unreleased event"
        return original(events)

    monkeypatch.setattr(engine_module, "detect", spy)
    service.start()
    for _ in range(20):
        clock.now += 1.0
        service.advance()
    assert seen and all(ids <= set(order[: service.released]) for ids in seen)


def test_pause_stops_release_and_resume_continues_without_duplicates() -> None:
    service, clock = replay()
    service.start()
    clock.now += 1.0
    service.advance()
    service.pause()
    clock.now += 100.0
    assert service.advance() == 0 and service.summary()["released"] == 5
    service.resume()
    clock.now += 1.0
    service.advance()
    released_ids = [row["event_id"] for row in service.recent_events()]
    assert service.summary()["released"] == 10
    assert len(released_ids) == len(set(released_ids))


def test_replay_completes_when_every_event_is_released_and_processed() -> None:
    service, clock = replay()
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["state"] == "completed"
    assert summary["generated"] == summary["released"] == summary["processed"] == 1500
    assert summary["pending"] == 0
    assert "Replay finished" in summary["message"]


def test_replay_is_reproducible_for_the_same_seed_and_configuration() -> None:
    first, first_clock = replay(model=FlagEverything())
    second, second_clock = replay(model=FlagEverything())
    first.start()
    second.start()
    run_to_end(first, first_clock)
    run_to_end(second, second_clock)
    assert first.summary() == second.summary()
    assert first.alerts() == second.alerts()
    assert first.cases() == second.cases()


# --- controls: idempotence, reset, stop --------------------------------------


def test_controls_are_idempotent_in_every_state() -> None:
    service, clock = replay()
    service.pause()  # idle: no effect
    assert service.state is SimulationState.IDLE
    service.start()
    service.start()  # second start must not build a second source
    service.resume()  # running: no effect
    clock.now += 1.0
    service.advance()
    assert service.summary()["released"] == 5
    service.pause()
    service.pause()
    assert service.state is SimulationState.PAUSED


def test_reset_returns_to_idle_and_clears_everything_derived() -> None:
    service, clock = replay(model=FlagEverything())
    service.start()
    for _ in range(40):
        clock.now += 1.0
        service.advance()
    assert service.alerts() and service.cases() and service.activity()
    service.reset()
    summary = service.summary()
    assert summary["state"] == "idle" and summary["released"] == 0 and summary["processed"] == 0
    assert summary["rule_alerts"] == 0 and summary["cases_total"] == 0 and summary["investigations_completed"] == 0
    assert service.alerts() == [] and service.cases() == [] and service.activity() == [] and service.recent_events() == []


def test_reset_then_start_restarts_deterministically() -> None:
    service, clock = replay()
    service.start()
    run_to_end(service, clock)
    before = service.summary()
    service.reset()
    service.start()
    run_to_end(service, clock)
    assert service.summary()["released"] == before["released"]
    fresh, fresh_clock = replay()
    fresh.start()
    run_to_end(fresh, fresh_clock)
    assert service.summary()["rule_alerts"] == fresh.summary()["rule_alerts"] == before["rule_alerts"]
    assert service.alerts() == fresh.alerts()


def test_stop_ends_continuous_generation_for_good() -> None:
    clock = FakeClock()
    service = SimulationService(LiveConfig("continuous", 9), FlagNothing(), clock=clock)
    service.start()
    for _ in range(3):
        clock.now += 1.0
        service.advance()
    stopped_at = service.summary()["released"]
    assert stopped_at > 0
    service.stop()
    clock.now += 50.0
    assert service.advance() == 0
    summary = service.summary()
    assert summary["state"] == "completed" and "Stopped by user" in summary["message"]
    assert summary["released"] == stopped_at


def test_continuous_mode_keeps_producing_events_while_running() -> None:
    clock = FakeClock()
    service = SimulationService(LiveConfig("continuous", 9), FlagNothing(), clock=clock)
    service.start()
    released = []
    for _ in range(5):
        clock.now += 1.0
        service.advance()
        released.append(service.released)
    assert released == sorted(released) and released[-1] == 25


# --- errors ----------------------------------------------------------------------


def test_processing_failure_is_visible_and_recoverable(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    service, clock = replay()
    service.start()

    def broken(events):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated detector fault")

    with monkeypatch.context() as patch:
        patch.setattr(engine_module, "detect", broken)
        clock.now += 1.0
        service.advance()
    summary = service.summary()
    assert summary["state"] == "error"
    assert "Processing failed (RuntimeError)" in summary["error"]
    assert "simulated detector fault" not in summary["error"]  # no internal detail on the page
    service.reset()
    service.start()
    run_to_end(service, clock)
    assert service.summary()["state"] == "completed"


# --- bounded history and isolation ----------------------------------------------


def test_history_and_feeds_stay_bounded_during_a_long_continuous_run() -> None:
    clock = FakeClock()
    service = SimulationService(LiveConfig("continuous", 3, events_per_second=50.0), FlagEverything(), clock=clock)
    service.start()
    for _ in range(80):
        clock.now += 1.0
        service.advance()
    summary = service.summary()
    assert summary["retained_events"] <= MAX_BUFFER
    assert len(service.recent_events()) <= EVENT_FEED
    assert len(service.activity()) <= ACTIVITY_FEED
    assert len(service.cases()) <= MAX_HISTORY
    assert len(service.alerts()) <= 2 * MAX_HISTORY
    assert summary["released"] == 4000 and summary["generated"] >= summary["released"]


def test_retained_events_are_inside_the_retention_window() -> None:
    service, clock = replay(model=FlagNothing())
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["retention_hours"] == RETENTION.total_seconds() / 3600
    assert summary["retained_events"] < summary["released"]  # old events have left the buffer


def test_live_cases_are_triaged_and_left_for_a_manual_investigation() -> None:
    service, clock = replay(scenario="Benign only", model=FlagEverything())
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    ml_only = [case for case in service.cases() if case["kind"] == "ml_only"]
    assert ml_only
    assert all(case["verdict"] == "not investigated" for case in ml_only)
    assert summary["investigations_completed"] == 0
    assert summary["ml_only_not_investigated"] == len(service.cases())
    queued = ml_only[0]
    assert queued["mode"] == "not investigated" and queued["review"] == "not reviewed"
    assert queued["priority"] == "ml_untriaged"


def test_a_rule_case_removes_the_standalone_ml_case_for_the_same_event() -> None:
    service, clock = replay(scenario="Bruteforce only", model=FlagEverything())
    service.start()
    run_to_end(service, clock)
    rule_events = {
        event_id
        for record in service._cases.values()
        if record.case.case_kind == "rule_backed"
        for event_id in record.case.event_ids
    }
    assert rule_events
    for case in service.cases():
        if case["kind"] != "ml_only":
            continue
        record = service.case_record(case["case_id"])
        assert record is not None
        assert record.case.event_ids[0] not in rule_events
        assert case["status"] == "open"


def test_ml_only_case_stays_in_the_queue_after_the_event_leaves_the_window() -> None:
    service, clock = replay(scenario="Benign only", model=FlagEverything())
    service.start()
    run_to_end(service, clock)
    retained = {event.event_id for event in service._buffer}
    aged_out = [
        case
        for case in service.cases()
        if case["kind"] == "ml_only"
        and service.case_record(case["case_id"]).case.event_ids[0] not in retained  # type: ignore[union-attr]
    ]
    assert aged_out
    assert service.summary()["ml_only_cases_open"] == sum(case["kind"] == "ml_only" for case in service.cases())


def test_rule_and_ml_cases_are_both_present_with_the_real_baseline_model() -> None:
    from login_anomaly.evaluation.experiment import train_baseline

    service, clock = replay(model=train_baseline()[0])
    service.start()
    run_to_end(service, clock)
    queued = service.cases()
    assert queued
    assert "ml_only" in {case["kind"] for case in queued}
    assert "rule_high" not in {case["priority"] for case in queued}
    assert {case["verdict"] for case in queued} == {"not investigated"}


def test_live_queue_names_the_manual_provider_without_running_it() -> None:
    service, clock = replay(model=FlagEverything())
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["investigations_completed"] == 0
    assert summary["agent_mode"] == "mock"
    assert summary["provider_id"].startswith("deterministic")
    assert summary["tool_errors"] == 0


def test_separate_sessions_do_not_share_state() -> None:
    first, first_clock = replay()
    second, _ = replay()
    first.start()
    first_clock.now += 1.0
    first.advance()
    second.start()
    assert first.summary()["released"] == 5
    assert second.summary()["released"] == 0 and second.summary()["cases_total"] == 0


def test_a_growing_campaign_is_one_incident_not_one_per_new_event() -> None:
    # Two bruteforce campaigns: each grows event by event as its window slides, yet must stay two incidents.
    service, clock = replay(scenario="Bruteforce only", model=FlagNothing())
    service.start()
    run_to_end(service, clock)
    assert service.summary()["rule_alerts"] == 2


# --- detector flags -----------------------------------------------------------


def test_detector_flags_validation() -> None:
    with pytest.raises(ValueError, match="enable_rules must be a boolean"):
        LiveConfig("replay", seed=1, enable_rules="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="enable_ml must be a boolean"):
        LiveConfig("replay", seed=1, enable_ml=1)  # type: ignore[arg-type]


def test_detector_flags_affect_simulation_id() -> None:
    both = LiveConfig("replay", seed=1, enable_rules=True, enable_ml=True)
    rules_only = LiveConfig("replay", seed=1, enable_rules=True, enable_ml=False)
    ml_only = LiveConfig("replay", seed=1, enable_rules=False, enable_ml=True)
    none = LiveConfig("replay", seed=1, enable_rules=False, enable_ml=False)

    ids = {engine_module._simulation_id(c) for c in (both, rules_only, ml_only, none)}
    assert len(ids) == 4


def test_rules_only_mode_disables_ml_scoring() -> None:
    clock = FakeClock()
    service = SimulationService(
        LiveConfig("replay", seed=31, scenario="Mixed campaigns", enable_rules=True, enable_ml=False),
        FlagEverything(),
        clock=clock,
    )
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["enable_rules"] is True
    assert summary["enable_ml"] is False
    assert summary["detector_mode"] == "rules_only"
    assert summary["rule_alerts"] > 0
    assert summary["ml_positive_events"] == 0
    assert all(c["kind"] == "rule_backed" for c in service.cases())


def test_ml_only_mode_disables_rule_detection() -> None:
    clock = FakeClock()
    service = SimulationService(
        LiveConfig("replay", seed=31, scenario="Mixed campaigns", enable_rules=False, enable_ml=True),
        FlagEverything(),
        clock=clock,
    )
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["enable_rules"] is False
    assert summary["enable_ml"] is True
    assert summary["detector_mode"] == "ml_only"
    assert summary["rule_alerts"] == 0
    assert summary["ml_positive_events"] > 0
    assert all(c["kind"] == "ml_only" for c in service.cases())


def test_no_detector_mode_serves_as_ingestion_baseline() -> None:
    clock = FakeClock()
    service = SimulationService(
        LiveConfig("replay", seed=31, scenario="Mixed campaigns", enable_rules=False, enable_ml=False),
        FlagEverything(),
        clock=clock,
    )
    service.start()
    run_to_end(service, clock)
    summary = service.summary()
    assert summary["enable_rules"] is False
    assert summary["enable_ml"] is False
    assert summary["detector_mode"] == "none"
    assert summary["rule_alerts"] == 0
    assert summary["ml_positive_events"] == 0
    assert summary["cases_total"] == 0
    assert summary["released"] == 1500
    assert summary["processed"] == 1500
    assert len(service.cases()) == 0
    assert len(service.alerts()) == 0
