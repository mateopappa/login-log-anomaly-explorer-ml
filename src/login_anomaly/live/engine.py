"""SOC Live service: releases events over time and runs the detectors on what is released.

Only released events enter ``_buffer``. Every detector, correlation step, and investigation reads
that buffer, so nothing can see a future event or a label. The service is synchronous: a Streamlit
fragment calls ``advance()`` on each refresh, and the clock is injected so tests can step it.

Two kinds of state:

- Retained events (``RETENTION`` by simulated time, hard cap ``MAX_BUFFER``). Rules and features
  look back at most 120 minutes, so this is the only context detection uses.
- History (incidents and case records, at most ``MAX_HISTORY`` each). A record keeps the event rows it
  was built from, so an earlier alert or investigation stays visible after its events leave the buffer.
  History is never re-detected: a record only changes when new retained events extend it.

Lifecycle: IDLE -> RUNNING <-> PAUSED -> COMPLETED, with ERROR reachable from RUNNING or PAUSED
and left only by ``reset()``. Replay completes when every event is released and processed.
Continuous runs until ``stop()``.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Literal

from login_anomaly.agentic.case_investigator import CaseInvestigationRun
from login_anomaly.agentic.provider import InvestigatorProvider, MockInvestigatorProvider
from login_anomaly.agentic.reviewer import InvestigationReview
from login_anomaly.correlation import InvestigationCase, MlPositiveSignal, RuleAlertSignal, correlate_signals, make_ml_positive_signal
from login_anomaly.detection.rules import Alert, Severity, detect
from login_anomaly.events import AuthEvent
from login_anomaly.live.sources import ATTACK_FAMILIES, REPLAY_SCENARIOS, ContinuousSource, ReplaySource, replay_events
from login_anomaly.ml.features import feature_matrix
from login_anomaly.ml.model import DECISION_THRESHOLD, predict_malicious
from login_anomaly.simulation.config import validate_seed

MIN_RATE = 1.0
MAX_RATE = 50.0
DEFAULT_RATE = 5.0
MAX_RELEASE_PER_TICK = 50
RETENTION = timedelta(hours=2)
MAX_BUFFER = 5000
MAX_HISTORY = 200
EVENT_FEED = 40
ACTIVITY_FEED = 200
TRANSITION_LOG = 100
MODEL_RUN_ID = "live-rf-baseline"


class SimulationState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass(frozen=True)
class LiveConfig:
    mode: Literal["replay", "continuous"]
    seed: int
    scenario: str = "Mixed campaigns"
    attacks: frozenset[str] = frozenset(ATTACK_FAMILIES)
    events_per_second: float = DEFAULT_RATE
    enable_rules: bool = True
    enable_ml: bool = True

    def __post_init__(self) -> None:
        if self.mode not in ("replay", "continuous"):
            raise ValueError("mode must be 'replay' or 'continuous'")
        validate_seed(self.seed)
        if self.mode == "replay" and self.scenario not in REPLAY_SCENARIOS:
            raise ValueError(f"unknown replay scenario {self.scenario!r}")
        if not isinstance(self.attacks, frozenset) or not self.attacks <= frozenset(ATTACK_FAMILIES):
            raise ValueError(f"attacks must be a subset of {list(ATTACK_FAMILIES)}")
        rate = self.events_per_second
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not MIN_RATE <= rate <= MAX_RATE:
            raise ValueError(f"events_per_second must be a number from {MIN_RATE:g} to {MAX_RATE:g}")
        if not isinstance(self.enable_rules, bool):
            raise ValueError("enable_rules must be a boolean")
        if not isinstance(self.enable_ml, bool):
            raise ValueError("enable_ml must be a boolean")


@dataclass(frozen=True)
class Incident:
    """A rule alert that keeps its identity while its window grows. Detector ids are not stable."""

    incident_id: str
    rule_id: str
    severity: Severity
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    evidence: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class CaseRecord:
    """One case and its investigation. ``run`` and ``review`` are None when the ML-only budget was used up."""

    case: InvestigationCase
    run: CaseInvestigationRun | None
    review: InvestigationReview | None
    events: tuple[dict[str, Any], ...]


class SimulationService:
    # Declared once here; ``_clear`` sets the initial values.
    _state: SimulationState
    _message: str
    _error: str | None
    _source: ReplaySource | ContinuousSource | None
    _elapsed: float
    _segment_started: float | None

    def __init__(
        self,
        config: LiveConfig,
        model: object,
        *,
        clock: Callable[[], float] = time.monotonic,
        provider: InvestigatorProvider | None = None,
    ) -> None:
        self.config = config
        self._model = model
        self._clock = clock
        self._provider: InvestigatorProvider = provider or MockInvestigatorProvider()
        self.simulation_id = _simulation_id(config)
        self._clear()

    # --- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        if self.state is not SimulationState.IDLE:
            return
        try:
            self._source = self._build_source()
        except ValueError as error:
            self._fail(f"Could not prepare the events: {error}")
            return
        self._segment_started = self._clock()
        self._set_state(SimulationState.RUNNING, f"Running ({self.config.mode}).")

    def pause(self) -> None:
        if self.state is SimulationState.RUNNING:
            self._elapsed = self._elapsed_now()
            self._segment_started = None
            self._set_state(SimulationState.PAUSED, "Paused. No events are released while paused.")

    def resume(self) -> None:
        if self.state is SimulationState.PAUSED:
            self._segment_started = self._clock()
            self._set_state(SimulationState.RUNNING, f"Running ({self.config.mode}).")

    def stop(self) -> None:
        """Stop a continuous run for good. Generation ends; the session stays readable until reset."""
        if self.state in (SimulationState.RUNNING, SimulationState.PAUSED):
            self._finish("Stopped by user. Event generation has stopped.")

    def reset(self) -> None:
        self._clear()

    def advance(self) -> int:
        """Release the events the elapsed simulation time has earned. Returns how many were released."""
        if self.state is not SimulationState.RUNNING or self._source is None:
            return 0
        released = 0
        try:
            due = int(self._elapsed_now() * self.config.events_per_second) - self._released
            batch = self._source.take(min(max(due, 0), MAX_RELEASE_PER_TICK))
            if batch:
                self._process(batch)
                released = len(batch)
            if self.config.mode == "replay" and self._source.pending() == 0:
                self._finish("Replay finished. Every event was released and processed.")
        except Exception as error:  # the page must show the failure, not crash; reset recovers
            self._fail(f"Processing failed ({type(error).__name__}). Reset to start again.")
        return released

    # --- read-only views for the presentation layer ------------------------------

    @property
    def state(self) -> SimulationState:
        return self._state

    @property
    def released(self) -> int:
        return self._released

    def summary(self) -> dict[str, Any]:
        elapsed = self._elapsed_now()
        records = list(self._cases.values())
        queued = self.cases()
        return {
            "simulation_id": self.simulation_id,
            "state": self._state.value,
            "message": self._message,
            "mode": self.config.mode,
            "seed": self.config.seed,
            "scenario": self.config.scenario if self.config.mode == "replay" else None,
            "attacks": sorted(self.config.attacks) if self.config.mode == "continuous" else None,
            "configured_rate": self.config.events_per_second,
            "enable_rules": self.config.enable_rules,
            "enable_ml": self.config.enable_ml,
            "detector_mode": (
                "rules_and_ml"
                if self.config.enable_rules and self.config.enable_ml
                else ("rules_only" if self.config.enable_rules else ("ml_only" if self.config.enable_ml else "none"))
            ),
            "effective_rate": round(self._released / elapsed, 2) if elapsed > 0 else 0.0,
            "elapsed_seconds": round(elapsed, 1),
            "generated": self._source.generated() if self._source else 0,
            "released": self._released,
            "processed": self._processed,
            "pending": self._source.pending() if self._source else 0,
            "simulated_time": self._latest.isoformat() if self._latest else None,
            "retained_events": len(self._buffer),
            "retention_hours": RETENTION.total_seconds() / 3600,
            "rule_alerts": self._incidents_created,
            "ml_positive_events": self._ml_positive_total,
            "cases_total": self._cases_opened,
            "cases_open": len(queued),
            "rule_backed_cases_open": sum(row["kind"] == "rule_backed" for row in queued),
            "ml_only_cases_open": sum(row["kind"] == "ml_only" for row in queued),
            "investigations_completed": self._investigations,
            "ml_only_not_investigated": sum(record.run is None for record in records),
            "tool_calls": self._tool_calls,
            "tool_errors": self._tool_errors,
            "agent_mode": self._provider.mode,
            "provider_id": self._provider.provider_id,
            "latency_ms_last_batch": round(self._latency_last_ms, 3),
            "latency_ms_total": round(self._latency_total_ms, 3),
            "error": self._error,
            "transitions": [{"state": state.value, "elapsed_seconds": at, "message": text} for state, at, text in self._transitions],
        }

    def recent_events(self) -> list[dict[str, Any]]:
        return list(self._recent_events)

    def activity(self) -> list[dict[str, Any]]:
        return list(reversed(self._activity))

    def alerts(self) -> list[dict[str, Any]]:
        """Rule incidents and ML-only cases, newest first. Carries the case id where one exists."""
        case_for_incident = {
            signal.alert_id: record.case.case_id
            for record in self._cases.values()
            if record.case.case_id in self._active_case_ids
            for signal in record.case.signals
            if isinstance(signal, RuleAlertSignal)
        }
        rows = [
            {
                "alert_id": incident.incident_id,
                "method": "rules",
                "rule": incident.rule_id,
                "severity": incident.severity.value,
                "first_seen": incident.first_seen.isoformat(),
                "events": len(incident.event_ids),
                "event_ids": list(incident.event_ids),
                "case_id": case_for_incident.get(incident.incident_id),
            }
            for incident in self._incidents.values()
        ]
        rows += [
            {
                "alert_id": record.case.case_id,
                "method": "ml",
                "rule": "ml_only",
                "severity": "untriaged",
                "first_seen": record.events[0]["timestamp_utc"],
                "events": len(record.case.event_ids),
                "event_ids": list(record.case.event_ids),
                "case_id": record.case.case_id,
            }
            for record in self._cases.values()
            if record.case.case_kind == "ml_only"
        ]
        return sorted(rows, key=lambda row: row["first_seen"], reverse=True)

    def cases(self) -> list[dict[str, Any]]:
        # A rule-backed case that ever covered an event absorbed any standalone ML-only case for it.
        rule_events = {
            event_id
            for record in self._cases.values()
            if record.case.case_kind == "rule_backed"
            for event_id in record.case.event_ids
        }
        rows = []
        for record in self._cases.values():
            if record.case.priority_hint == "rule_high":
                continue
            case_id = record.case.case_id
            if record.case.case_kind == "ml_only" and case_id not in self._active_case_ids and record.case.event_ids[0] in rule_events:
                status = "superseded by a rule-backed case"
            else:
                status = "open"
            rows.append(
                {
                    "case_id": case_id,
                    "kind": record.case.case_kind,
                    "status": status,
                    "events": len(record.case.event_ids),
                    "signals": len(record.case.signals),
                    "priority": record.case.priority_hint,
                    "mode": record.run.mode if record.run else "not investigated",
                    "verdict": record.run.result.verdict if record.run else "not investigated",
                    "review": record.review.quality if record.review else "not reviewed",
                }
            )
        return rows

    def case_record(self, case_id: str) -> CaseRecord | None:
        return self._cases.get(case_id)

    # --- internals --------------------------------------------------------------

    def _clear(self) -> None:
        self._state = SimulationState.IDLE
        self._message = "Not started."
        self._error = None
        self._source = None
        self._elapsed = 0.0
        self._segment_started = None
        self._transitions: deque[tuple[SimulationState, float, str]] = deque([(SimulationState.IDLE, 0.0, "Not started.")], maxlen=TRANSITION_LOG)
        self._released = 0
        self._processed = 0
        self._latest: datetime | None = None
        self._buffer: list[AuthEvent] = []
        self._incidents: dict[str, Incident] = {}
        self._incidents_created = 0
        self._next_incident = 1
        self._ml_signals: dict[str, MlPositiveSignal] = {}
        self._ml_flagged_ids: set[str] = set()
        self._ml_positive_total = 0
        self._cases: dict[str, CaseRecord] = {}
        self._active_case_ids: set[str] = set()
        self._cases_opened = 0
        self._investigations = 0
        self._tool_calls = 0
        self._tool_errors = 0
        self._latency_last_ms = 0.0
        self._latency_total_ms = 0.0
        self._recent_events: deque[dict[str, Any]] = deque(maxlen=EVENT_FEED)
        self._activity: deque[dict[str, Any]] = deque(maxlen=ACTIVITY_FEED)
        self._sequence = 0

    def _build_source(self) -> ReplaySource | ContinuousSource:
        if self.config.mode == "replay":
            return ReplaySource(replay_events(self.config.scenario, self.config.seed))
        return ContinuousSource(self.config.seed, self.config.attacks)

    def _elapsed_now(self) -> float:
        if self._segment_started is None:
            return self._elapsed
        return self._elapsed + (self._clock() - self._segment_started)

    def _set_state(self, state: SimulationState, message: str) -> None:
        self._state = state
        self._message = message
        self._transitions.append((state, round(self._elapsed_now(), 1), message))

    def _finish(self, message: str) -> None:
        self._elapsed = self._elapsed_now()
        self._segment_started = None
        self._set_state(SimulationState.COMPLETED, message)

    def _fail(self, message: str) -> None:
        self._error = message
        if self._segment_started is not None:
            self._elapsed = self._elapsed_now()
        self._segment_started = None
        self._set_state(SimulationState.ERROR, message)

    def _process(self, batch: tuple[AuthEvent, ...]) -> None:
        started = self._clock()
        self._released += len(batch)
        self._buffer.extend(batch)
        self._buffer.sort(key=lambda event: (event.timestamp_utc, event.event_id))
        self._latest = self._buffer[-1].timestamp_utc
        self._recent_events.extend(_observable_row(event) for event in batch)

        # Trim first: every later step may only refer to events that are still retained.
        self._trim()
        if self.config.enable_ml:
            self._score(batch)
        if self.config.enable_rules:
            self._merge_incidents(detect(self._buffer))
        alerts = self._correlation_alerts() if self.config.enable_rules else []
        ml_signals = list(self._ml_signals.values()) if self.config.enable_ml else []
        cases = correlate_signals(self._buffer, alerts, ml_signals, dataset_id=self.simulation_id)
        self._investigate(cases)
        self._processed += len(batch)
        self._latency_last_ms = (self._clock() - started) * 1000
        self._latency_total_ms += self._latency_last_ms

    def _trim(self) -> None:
        cutoff = self._buffer[-1].timestamp_utc - RETENTION
        kept = [event for event in self._buffer if event.timestamp_utc >= cutoff][-MAX_BUFFER:]
        if len(kept) == len(self._buffer):
            return
        self._buffer = kept
        retained = {event.event_id for event in kept}
        self._ml_signals = {key: value for key, value in self._ml_signals.items() if key in retained}

    def _score(self, batch: tuple[AuthEvent, ...]) -> None:
        # Features are causal, so each row depends only on events up to its own timestamp.
        ids, rows = feature_matrix(self._buffer)
        row_by_id = dict(zip(ids, rows))
        batch_ids = [event.event_id for event in batch if event.event_id in row_by_id]  # late events may already be trimmed
        predictions = predict_malicious(self._model, [row_by_id[event_id] for event_id in batch_ids])  # type: ignore[arg-type]
        for event_id, prediction in zip(batch_ids, predictions):
            if prediction == 1:
                self._ml_signals[event_id] = make_ml_positive_signal(self.simulation_id, event_id, MODEL_RUN_ID, DECISION_THRESHOLD)
                if event_id not in self._ml_flagged_ids:
                    self._ml_positive_total += 1
                self._ml_flagged_ids.add(event_id)

    def _merge_incidents(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            ids = set(alert.event_ids)
            match = next(
                (inc for inc in self._incidents.values() if inc.rule_id == alert.rule_id and ids & set(inc.event_ids)),
                None,
            )
            if match is None:
                incident_id = f"inc-{self._incidents_created + 1:04d}"
                self._incidents_created += 1
                self._incidents[incident_id] = Incident(
                    incident_id, alert.rule_id, alert.severity, tuple(alert.event_ids), alert.first_seen, alert.last_seen, alert.evidence, alert.explanation
                )
                self._evict(self._incidents)
                self._log("alert", f"{alert.rule_id} alert {incident_id} on {len(alert.event_ids)} events")
            elif not ids <= set(match.event_ids):
                # Arrival order is kept: the case builder sorts events by time when it needs to.
                merged = tuple(dict.fromkeys((*match.event_ids, *alert.event_ids)))
                self._incidents[match.incident_id] = Incident(
                    match.incident_id, match.rule_id, match.severity, merged, match.first_seen, alert.last_seen, match.evidence, match.explanation
                )

    def _correlation_alerts(self) -> list[Alert]:
        # Correlation may only see retained events; history keeps the full evidence for display.
        retained = {event.event_id for event in self._buffer}
        alerts = []
        for inc in self._incidents.values():
            ids = tuple(event_id for event_id in inc.event_ids if event_id in retained)
            if ids:
                alerts.append(Alert(inc.incident_id, inc.rule_id, inc.severity, ids, inc.first_seen, inc.last_seen, inc.evidence, inc.explanation))
        return alerts

    def _investigate(self, cases: tuple[InvestigationCase, ...]) -> None:
        events = tuple(self._buffer)
        # The detector window is 2 hours. The analyst queue is not: an ML-only case stays
        # after its event leaves the buffer. It leaves the queue only when a rule case
        # covers that same event.
        rule_event_ids = {
            event_id
            for case in cases
            if case.case_kind == "rule_backed"
            for event_id in case.event_ids
        }
        rule_event_ids.update(
            event_id
            for record in self._cases.values()
            if record.case.case_kind == "rule_backed"
            for event_id in record.case.event_ids
        )
        self._cases = {
            key: record
            for key, record in self._cases.items()
            if record.case.case_kind == "rule_backed"
            or (record.case.event_ids and record.case.event_ids[0] not in rule_event_ids)
        }
        active: set[str] = set()
        for case in cases:
            active.add(case.case_id)
            previous = self._cases.get(case.case_id)
            if previous is not None and previous.case.event_ids == case.event_ids:
                continue
            if previous is None:
                self._cases_opened += 1
                self._log("case_opened", f"{case.case_kind} case {case.case_id} opened with {len(case.event_ids)} events")
            rows = tuple(_observable_row(event) for event in events if event.event_id in set(case.event_ids))
            # Triage only. The analyst starts the investigation from the case dossier.
            self._remember(CaseRecord(case, None, None, rows), active)
        self._active_case_ids = active

    def _remember(self, record: CaseRecord, active: set[str]) -> None:
        self._cases[record.case.case_id] = record
        self._evict(self._cases, keep=active)

    def _evict(self, store: dict[str, Any], keep: frozenset[str] | set[str] = frozenset()) -> None:
        # Oldest first, never a case that is still open. Dicts keep insertion order.
        while len(store) > MAX_HISTORY:
            victim = next((key for key in store if key not in keep), None)
            if victim is None:
                break
            del store[victim]

    def _log(self, kind: str, text: str) -> None:
        self._sequence += 1
        self._activity.append({"seq": self._sequence, "kind": kind, "simulated_time": self._latest.isoformat() if self._latest else None, "text": text})


def _observable_row(event: AuthEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp_utc": event.timestamp_utc.isoformat(),
        "account_id": event.account_id,
        "source_ip": event.source_ip,
        "outcome": event.outcome.value,
        "country_code": event.country_code,
    }


def _simulation_id(config: LiveConfig) -> str:
    payload = {
        "mode": config.mode,
        "seed": config.seed,
        "scenario": config.scenario,
        "attacks": sorted(config.attacks),
        "enable_rules": config.enable_rules,
        "enable_ml": config.enable_ml,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"sim-{digest[:12]}"
