"""Acceptance tests for deterministic, label-free detector-signal correlation."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.correlation import (
    CorrelationError,
    MlPositiveSignal,
    correlate_signals,
    dataset_id_for,
    make_ml_positive_signal,
)
from login_anomaly.detection.rules import Alert, Severity
from login_anomaly.events import AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)
DATASET_ID = "dataset-test"


def event(event_id: str, minutes: int, account: str = "acct-01") -> AuthEvent:
    return AuthEvent(event_id, T0 + timedelta(minutes=minutes), account, "10.1.1.1", Outcome.SUCCESS, "AR")


def alert(alert_id: str, event_ids: tuple[str, ...], *, severity: Severity = Severity.HIGH) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="impossible_travel",
        severity=severity,
        event_ids=event_ids,
        first_seen=T0,
        last_seen=T0 + timedelta(minutes=10),
        evidence=("native evidence",),
        explanation="native explanation",
    )


def ml(event_id: str, run: str = "model-run-1") -> MlPositiveSignal:
    return make_ml_positive_signal(DATASET_ID, event_id, run, 0.5)


def test_exact_match_creates_one_rule_case_and_preserves_native_alert() -> None:
    alerts = (alert("alt-1", ("evt-2", "evt-1")),)
    cases = correlate_signals((event("evt-1", 1), event("evt-2", 2)), alerts, (ml("evt-2"),), dataset_id=DATASET_ID)
    assert len(cases) == 1
    case = cases[0]
    rule_signal, ml_signal = case.signals
    assert case.case_kind == "rule_backed"
    assert case.event_ids == ("evt-1", "evt-2")
    assert rule_signal.event_ids == alerts[0].event_ids  # type: ignore[union-attr]
    assert rule_signal.explanation == alerts[0].explanation  # type: ignore[union-attr]
    assert rule_signal.evidence == alerts[0].evidence  # type: ignore[union-attr]
    assert ml_signal == ml("evt-2")
    assert case.associations[0].basis == "exact_alert_event_id"


def test_multiple_ml_signals_attach_to_one_alert_case() -> None:
    cases = correlate_signals(
        (event("evt-1", 1), event("evt-2", 2)),
        (alert("alt-1", ("evt-1", "evt-2")),),
        (ml("evt-1"), ml("evt-2")),
        dataset_id=DATASET_ID,
    )
    assert len(cases) == 1
    assert len(cases[0].signals) == 3
    assert {item.event_id for item in cases[0].associations} == {"evt-1", "evt-2"}


def test_unmatched_ml_signal_creates_ml_only_case_without_alert() -> None:
    cases = correlate_signals((event("evt-1", 1),), (), (ml("evt-1"),), dataset_id=DATASET_ID)
    assert len(cases) == 1
    assert cases[0].case_kind == "ml_only"
    assert cases[0].priority_hint == "ml_untriaged"
    assert all(not hasattr(signal, "alert_id") for signal in cases[0].signals)
    assert cases[0].associations[0].basis == "unmatched"


def test_same_account_alerts_remain_separate() -> None:
    events = (event("evt-1", 1), event("evt-2", 2), event("evt-3", 3))
    cases = correlate_signals(events, (alert("alt-1", ("evt-1",)), alert("alt-2", ("evt-2",))), (), dataset_id=DATASET_ID)
    assert len(cases) == 2
    assert {case.event_ids for case in cases} == {("evt-1",), ("evt-2",)}


def test_native_alert_event_order_is_preserved_while_case_events_are_chronological() -> None:
    native = alert("alt-1", ("evt-2", "evt-1"))
    case = correlate_signals((event("evt-1", 1), event("evt-2", 2)), (native,), (), dataset_id=DATASET_ID)[0]
    assert case.signals[0].event_ids == ("evt-2", "evt-1")  # type: ignore[union-attr]
    assert case.event_ids == ("evt-1", "evt-2")


def test_identical_input_and_permutations_are_normalized() -> None:
    events = (event("evt-2", 1), event("evt-1", 1), event("evt-3", 3))
    alerts = (alert("alt-2", ("evt-2",)), alert("alt-1", ("evt-1",)))
    signals = (ml("evt-1"), ml("evt-3"))
    first = correlate_signals(events, alerts, signals, dataset_id=DATASET_ID)
    second = correlate_signals(tuple(reversed(events)), tuple(reversed(alerts)), tuple(reversed(signals)), dataset_id=DATASET_ID)
    assert first == second
    assert first[0].event_ids == ("evt-1",)


def test_every_input_signal_is_preserved_exactly_once() -> None:
    alerts = (alert("alt-1", ("evt-1",)), alert("alt-2", ("evt-2",)))
    signals = (ml("evt-1"), ml("evt-2"), ml("evt-3"))
    cases = correlate_signals((event("evt-1", 1), event("evt-2", 2), event("evt-3", 3)), alerts, signals, dataset_id=DATASET_ID)
    output_signals = [signal for case in cases for signal in case.signals]
    assert sum(isinstance(signal, MlPositiveSignal) for signal in output_signals) == len(signals)
    assert sum(type(signal).__name__ == "RuleAlertSignal" for signal in output_signals) == len(alerts)
    assert {signal.signal_id for signal in output_signals} == {signal.signal_id for signal in signals} | {
        case.signals[0].signal_id for case in cases if case.case_kind == "rule_backed"
    }


@pytest.mark.parametrize(
    "alerts, signals, match",
    [
        ((alert("alt-1", ("evt-missing",)),), (), "references missing event_ids"),
        ((), (ml("evt-missing"),), "references missing event_ids"),
    ],
)
def test_missing_event_references_fail_clearly(alerts: tuple[Alert, ...], signals: tuple[MlPositiveSignal, ...], match: str) -> None:
    with pytest.raises(CorrelationError, match=match):
        correlate_signals((event("evt-1", 1),), alerts, signals, dataset_id=DATASET_ID)


def test_ambiguous_exact_match_stays_ml_only_with_candidates() -> None:
    cases = correlate_signals(
        (event("evt-1", 1),),
        (alert("alt-1", ("evt-1",)), alert("alt-2", ("evt-1",))),
        (ml("evt-1"),),
        dataset_id=DATASET_ID,
    )
    rule_cases = [case for case in cases if case.case_kind == "rule_backed"]
    ml_case = next(case for case in cases if case.case_kind == "ml_only")
    assert len(rule_cases) == 2 and all(len(case.signals) == 1 for case in rule_cases)
    association = ml_case.associations[0]
    assert association.basis == "ambiguous_exact_match"
    assert len(association.candidate_rule_signal_ids) == 2


def test_correlation_operates_on_event_only_dataset_without_ground_truth() -> None:
    dataset = generate(
        GeneratorConfig(seed=9, start_utc=T0, duration_hours=1, n_accounts=2, n_events=3)
    )
    dataset_id = dataset_id_for(dataset.manifest)
    target = dataset.events[0]
    cases = correlate_signals(dataset.events, (), (make_ml_positive_signal(dataset_id, target.event_id, "model-run-1", 0.5),), dataset_id=dataset_id)
    assert cases[0].event_ids == (target.event_id,)


def test_case_event_order_uses_event_id_as_timestamp_tie_breaker() -> None:
    case = correlate_signals((event("evt-b", 1), event("evt-a", 1)), (alert("alt-1", ("evt-b", "evt-a")),), (), dataset_id=DATASET_ID)[0]
    assert case.event_ids == ("evt-a", "evt-b")


def test_multiple_distinct_ml_signals_for_one_event_remain_visible() -> None:
    cases = correlate_signals((event("evt-1", 1),), (), (ml("evt-1", "model-run-1"), ml("evt-1", "model-run-2")), dataset_id=DATASET_ID)
    assert len(cases) == 1
    assert len(cases[0].signals) == 2
    assert len(cases[0].associations) == 2


def test_ml_signal_from_another_dataset_is_rejected() -> None:
    foreign = replace(ml("evt-1"), dataset_id="dataset-other")
    with pytest.raises(CorrelationError, match="belongs to dataset_id"):
        correlate_signals((event("evt-1", 1),), (), (foreign,), dataset_id=DATASET_ID)


def test_duplicate_signal_and_alert_ids_fail_instead_of_overwriting() -> None:
    signal = ml("evt-1")
    with pytest.raises(CorrelationError, match="duplicate ML signal_id"):
        correlate_signals((event("evt-1", 1),), (), (signal, signal), dataset_id=DATASET_ID)
    with pytest.raises(CorrelationError, match="duplicate alert_id"):
        correlate_signals((event("evt-1", 1),), (alert("alt-1", ("evt-1",)), alert("alt-1", ("evt-1",))), (), dataset_id=DATASET_ID)


def test_rule_and_ml_signal_id_collision_fails_instead_of_corrupting_provenance() -> None:
    native = alert("alt-1", ("evt-1",))
    rule_case = correlate_signals((event("evt-1", 1),), (native,), (), dataset_id=DATASET_ID)[0]
    rule_signal_id = rule_case.signals[0].signal_id
    conflicting = replace(ml("evt-1"), signal_id=rule_signal_id)
    with pytest.raises(CorrelationError, match="shared by rule and ML"):
        correlate_signals((event("evt-1", 1),), (native,), (conflicting,), dataset_id=DATASET_ID)


def test_invalid_ml_signal_contract_is_rejected() -> None:
    with pytest.raises(CorrelationError, match="prediction"):
        replace(ml("evt-1"), prediction=0)
