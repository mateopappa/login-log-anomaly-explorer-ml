"""Deterministic correlation of native rule alerts and ML-positive event signals.

This module is runtime-only infrastructure.  It accepts observable events, native
``Alert`` objects, and caller-supplied ML-positive signals; it never reads labels,
campaigns, or evaluation metadata.  The deliberately conservative policy associates
an ML signal with a rule alert only when they name the exact same event id.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal

from login_anomaly.detection.rules import Alert, Severity
from login_anomaly.events import AuthEvent
from login_anomaly.simulation.manifest import DatasetManifest
from login_anomaly.validation import require_identifier, require_non_empty_str, require_utc

_PRIORITY_HINTS = frozenset({"rule_high", "rule_medium", "ml_untriaged"})
_ASSOCIATION_BASES = frozenset({"exact_alert_event_id", "unmatched", "ambiguous_exact_match"})


class CorrelationError(ValueError):
    """Raised when observable detector inputs cannot form trustworthy cases."""


def dataset_id_for(manifest: DatasetManifest) -> str:
    """Return a stable identifier derived only from existing dataset provenance."""
    if not isinstance(manifest, DatasetManifest):
        raise CorrelationError("manifest must be a DatasetManifest")
    return _stable_id("dataset", asdict(manifest))


def make_ml_positive_signal(
    dataset_id: str,
    event_id: str,
    model_run_id: str,
    threshold: float,
    *,
    score: float | None = None,
) -> MlPositiveSignal:
    """Build a deterministic ML-positive signal.

    ``model_run_id`` is intentionally a caller input: the current model API has
    no persisted model-artifact identifier.  The helper does not invent one.
    """
    _require_dataset_id(dataset_id)
    require_identifier(event_id, "event_id")
    require_identifier(model_run_id, "model_run_id")
    _require_probability(threshold, "threshold")
    if score is not None:
        _require_probability(score, "score")
    signal_id = _stable_id(
        "ml-signal",
        {
            "dataset_id": dataset_id,
            "event_id": event_id,
            "model_run_id": model_run_id,
            "threshold": threshold,
            "score": score,
            "prediction": 1,
        },
    )
    return MlPositiveSignal(signal_id, dataset_id, event_id, model_run_id, threshold, score)


@dataclass(frozen=True)
class MlPositiveSignal:
    """One positive event prediction from an identified model run."""

    signal_id: str
    dataset_id: str
    event_id: str
    model_run_id: str
    threshold: float
    score: float | None = None
    prediction: int = 1

    def __post_init__(self) -> None:
        require_identifier(self.signal_id, "signal_id")
        _require_dataset_id(self.dataset_id)
        require_identifier(self.event_id, "event_id")
        require_identifier(self.model_run_id, "model_run_id")
        _require_probability(self.threshold, "threshold")
        if self.score is not None:
            _require_probability(self.score, "score")
        if self.prediction != 1:
            raise CorrelationError("MlPositiveSignal prediction must be 1")


@dataclass(frozen=True)
class RuleAlertSignal:
    """A lossless runtime copy of one native rule alert."""

    signal_id: str
    alert_id: str
    rule_id: str
    severity: str
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    explanation: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.signal_id, "signal_id")
        require_identifier(self.alert_id, "alert_id")
        require_non_empty_str(self.rule_id, "rule_id")
        if self.severity not in {"medium", "high"}:
            raise CorrelationError("severity must be 'medium' or 'high'")
        if not isinstance(self.event_ids, tuple) or not self.event_ids:
            raise CorrelationError("event_ids must be a non-empty tuple")
        for event_id in self.event_ids:
            require_identifier(event_id, "event_ids item")
        require_utc(self.first_seen, "first_seen")
        require_utc(self.last_seen, "last_seen")
        if self.last_seen < self.first_seen:
            raise CorrelationError("last_seen must not precede first_seen")
        require_non_empty_str(self.explanation, "explanation")
        if not isinstance(self.evidence, tuple) or not all(isinstance(item, str) for item in self.evidence):
            raise CorrelationError("evidence must be a tuple of strings")


@dataclass(frozen=True)
class Association:
    """Why one ML signal belongs to this case, without changing either detector."""

    ml_signal_id: str
    rule_signal_id: str | None
    event_id: str
    basis: Literal["exact_alert_event_id", "unmatched", "ambiguous_exact_match"]
    candidate_rule_signal_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.ml_signal_id, "ml_signal_id")
        if self.rule_signal_id is not None:
            require_identifier(self.rule_signal_id, "rule_signal_id")
        require_identifier(self.event_id, "event_id")
        if self.basis not in _ASSOCIATION_BASES:
            raise CorrelationError(f"unknown association basis: {self.basis!r}")
        if not isinstance(self.candidate_rule_signal_ids, tuple):
            raise CorrelationError("candidate_rule_signal_ids must be a tuple")
        for signal_id in self.candidate_rule_signal_ids:
            require_identifier(signal_id, "candidate_rule_signal_ids item")
        if self.candidate_rule_signal_ids != tuple(sorted(set(self.candidate_rule_signal_ids))):
            raise CorrelationError("candidate_rule_signal_ids must be unique and sorted")
        if self.basis == "exact_alert_event_id":
            if self.rule_signal_id is None or self.candidate_rule_signal_ids != (self.rule_signal_id,):
                raise CorrelationError("exact association must name exactly one rule signal")
        elif self.rule_signal_id is not None:
            raise CorrelationError("only exact association may name a rule signal")
        elif self.basis == "unmatched" and self.candidate_rule_signal_ids:
            raise CorrelationError("unmatched association cannot have rule candidates")
        elif self.basis == "ambiguous_exact_match" and len(self.candidate_rule_signal_ids) < 2:
            raise CorrelationError("ambiguous association needs multiple rule candidates")


@dataclass(frozen=True)
class InvestigationCase:
    """Immutable, label-free case containing detector provenance and associations."""

    case_id: str
    dataset_id: str
    case_kind: Literal["rule_backed", "ml_only"]
    event_ids: tuple[str, ...]
    signals: tuple[RuleAlertSignal | MlPositiveSignal, ...]
    associations: tuple[Association, ...]
    priority_hint: Literal["rule_high", "rule_medium", "ml_untriaged"]

    def __post_init__(self) -> None:
        require_identifier(self.case_id, "case_id")
        _require_dataset_id(self.dataset_id)
        if self.case_kind not in {"rule_backed", "ml_only"}:
            raise CorrelationError(f"unknown case kind: {self.case_kind!r}")
        if not isinstance(self.event_ids, tuple) or not self.event_ids:
            raise CorrelationError("event_ids must be a non-empty tuple")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise CorrelationError("case event_ids must be unique")
        for event_id in self.event_ids:
            require_identifier(event_id, "event_ids item")
        if not isinstance(self.signals, tuple) or not self.signals:
            raise CorrelationError("signals must be a non-empty tuple")
        if not all(isinstance(signal, (RuleAlertSignal, MlPositiveSignal)) for signal in self.signals):
            raise CorrelationError("signals must be rule or ML signals")
        if not isinstance(self.associations, tuple) or not all(isinstance(item, Association) for item in self.associations):
            raise CorrelationError("associations must contain Association objects")
        if self.priority_hint not in _PRIORITY_HINTS:
            raise CorrelationError(f"unknown priority hint: {self.priority_hint!r}")


def correlate_signals(
    events: Iterable[AuthEvent],
    alerts: Iterable[Alert],
    ml_signals: Iterable[MlPositiveSignal],
    *,
    dataset_id: str,
) -> tuple[InvestigationCase, ...]:
    """Correlate native alerts and ML positives using exact event identity only.

    The function is pure and input-order independent.  Ambiguous ML-to-alert
    matches remain in a separate ML-only case rather than being attached to a
    possibly unrelated native alert.
    """
    _require_dataset_id(dataset_id)
    event_index = _event_index(events)
    rule_signals = _rule_signals(alerts, dataset_id, event_index)
    ml_entries = _ml_signals(ml_signals, event_index, dataset_id)
    conflicting_ids = sorted({signal.signal_id for signal in rule_signals} & {signal.signal_id for signal in ml_entries})
    if conflicting_ids:
        raise CorrelationError(f"signal_id is shared by rule and ML signals: {conflicting_ids}")

    candidates: dict[str, list[RuleAlertSignal]] = defaultdict(list)
    for signal in rule_signals:
        for event_id in signal.event_ids:
            candidates[event_id].append(signal)
    for value in candidates.values():
        value.sort(key=lambda signal: signal.signal_id)

    attached: dict[str, list[MlPositiveSignal]] = defaultdict(list)
    attached_associations: dict[str, list[Association]] = defaultdict(list)
    standalone: dict[str, list[MlPositiveSignal]] = defaultdict(list)
    standalone_associations: dict[str, list[Association]] = defaultdict(list)
    for ml_signal in ml_entries:
        matches = candidates.get(ml_signal.event_id, [])
        candidate_ids = tuple(item.signal_id for item in matches)
        if len(matches) == 1:
            rule_signal = matches[0]
            attached[rule_signal.signal_id].append(ml_signal)
            attached_associations[rule_signal.signal_id].append(
                Association(ml_signal.signal_id, rule_signal.signal_id, ml_signal.event_id, "exact_alert_event_id", candidate_ids)
            )
        else:
            basis: Literal["unmatched", "ambiguous_exact_match"] = "unmatched" if not matches else "ambiguous_exact_match"
            standalone[ml_signal.event_id].append(ml_signal)
            standalone_associations[ml_signal.event_id].append(
                Association(ml_signal.signal_id, None, ml_signal.event_id, basis, candidate_ids)
            )

    cases: list[InvestigationCase] = []
    for rule_signal in rule_signals:
        extra = tuple(sorted(attached[rule_signal.signal_id], key=lambda signal: signal.signal_id))
        associations = tuple(sorted(attached_associations[rule_signal.signal_id], key=lambda item: item.ml_signal_id))
        event_ids = _ordered_event_ids((*rule_signal.event_ids, *(signal.event_id for signal in extra)), event_index)
        priority: Literal["rule_high", "rule_medium"] = "rule_high" if rule_signal.severity == "high" else "rule_medium"
        cases.append(
            InvestigationCase(
                _stable_id("case", {"dataset_id": dataset_id, "rule_signal_id": rule_signal.signal_id}),
                dataset_id,
                "rule_backed",
                event_ids,
                (rule_signal, *extra),
                associations,
                priority,
            )
        )
    for event_id, signals in standalone.items():
        ordered_signals = tuple(sorted(signals, key=lambda signal: signal.signal_id))
        associations = tuple(sorted(standalone_associations[event_id], key=lambda item: item.ml_signal_id))
        cases.append(
            InvestigationCase(
                _stable_id("case", {"dataset_id": dataset_id, "ml_event_id": event_id}),
                dataset_id,
                "ml_only",
                (event_id,),
                ordered_signals,
                associations,
                "ml_untriaged",
            )
        )
    return tuple(sorted(cases, key=lambda case: _case_sort_key(case, event_index)))


def _event_index(events: Iterable[AuthEvent]) -> dict[str, AuthEvent]:
    index: dict[str, AuthEvent] = {}
    for event in events:
        if not isinstance(event, AuthEvent):
            raise CorrelationError("events must contain AuthEvent objects")
        if event.event_id in index:
            raise CorrelationError(f"duplicate event_id in events: {event.event_id!r}")
        index[event.event_id] = event
    return index


def _rule_signals(
    alerts: Iterable[Alert], dataset_id: str, event_index: dict[str, AuthEvent]
) -> tuple[RuleAlertSignal, ...]:
    result: list[RuleAlertSignal] = []
    seen_alert_ids: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, Alert):
            raise CorrelationError("alerts must contain Alert objects")
        if not isinstance(alert.severity, Severity):
            raise CorrelationError(f"alert {alert.alert_id!r} has an invalid severity")
        if alert.alert_id in seen_alert_ids:
            raise CorrelationError(f"duplicate alert_id: {alert.alert_id!r}")
        seen_alert_ids.add(alert.alert_id)
        _require_referenced_events(alert.event_ids, event_index, f"alert {alert.alert_id!r}")
        result.append(
            RuleAlertSignal(
                _stable_id("rule-signal", {"dataset_id": dataset_id, "alert_id": alert.alert_id}),
                alert.alert_id,
                alert.rule_id,
                alert.severity.value,
                alert.event_ids,
                alert.first_seen,
                alert.last_seen,
                alert.explanation,
                alert.evidence,
            )
        )
    return tuple(sorted(result, key=lambda signal: signal.signal_id))


def _ml_signals(
    signals: Iterable[MlPositiveSignal], event_index: dict[str, AuthEvent], dataset_id: str
) -> tuple[MlPositiveSignal, ...]:
    result = []
    seen_ids: set[str] = set()
    for signal in signals:
        if not isinstance(signal, MlPositiveSignal):
            raise CorrelationError("ml_signals must contain MlPositiveSignal objects")
        if signal.signal_id in seen_ids:
            raise CorrelationError(f"duplicate ML signal_id: {signal.signal_id!r}")
        seen_ids.add(signal.signal_id)
        if signal.dataset_id != dataset_id:
            raise CorrelationError(
                f"ML signal {signal.signal_id!r} belongs to dataset_id {signal.dataset_id!r}, not {dataset_id!r}"
            )
        _require_referenced_events((signal.event_id,), event_index, f"ML signal {signal.signal_id!r}")
        result.append(signal)
    return tuple(sorted(result, key=lambda signal: signal.signal_id))


def _require_referenced_events(event_ids: tuple[str, ...], event_index: dict[str, AuthEvent], source: str) -> None:
    missing = sorted(set(event_ids) - set(event_index))
    if missing:
        raise CorrelationError(f"{source} references missing event_ids: {missing}")


def _ordered_event_ids(event_ids: Iterable[str], event_index: dict[str, AuthEvent]) -> tuple[str, ...]:
    return tuple(sorted(set(event_ids), key=lambda event_id: (event_index[event_id].timestamp_utc, event_id)))


def _case_sort_key(case: InvestigationCase, event_index: dict[str, AuthEvent]) -> tuple[datetime, str]:
    return event_index[case.event_ids[0]].timestamp_utc, case.case_id


def _stable_id(prefix: str, payload: object) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str)
    return f"{prefix}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:24]}"


def _require_dataset_id(dataset_id: object) -> None:
    try:
        require_identifier(dataset_id, "dataset_id")
    except ValueError as error:
        raise CorrelationError(str(error)) from error


def _require_probability(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
        raise CorrelationError(f"{name} must be a number between 0 and 1")
