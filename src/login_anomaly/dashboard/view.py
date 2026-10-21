"""Dashboard logic without Streamlit. The app renders what this module computes, and these functions are tested.

Detection runs on ``EventDataset`` (events only). Comparison with ground truth runs on
``GeneratedDataset``, and only in the evaluation panel. Both come from the same build,
so their events are identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from login_anomaly.detection.rules import Alert, detect
from login_anomaly.ml.features import feature_matrix
from login_anomaly.ml.model import predict_malicious
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import EventDataset, generate
from login_anomaly.simulation.scenarios import ScenarioPlan


@dataclass(frozen=True)
class SessionConfig:
    seed: int
    n_events: int
    n_accounts: int
    duration_hours: int
    plan: ScenarioPlan

    def generator_config(self) -> GeneratorConfig:
        return GeneratorConfig(
            seed=self.seed,
            start_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_hours=self.duration_hours,
            n_accounts=self.n_accounts,
            n_events=self.n_events,
        )


def events_for(session: SessionConfig) -> EventDataset:
    """What detectors receive: events and manifest only."""
    return generate(session.generator_config(), session.plan)


def rule_alerts(events: EventDataset) -> list[Alert]:
    return detect(list(events.events))


def ml_flags(model: object, events: EventDataset) -> dict[str, int]:
    ids, rows = feature_matrix(events.events)
    return dict(zip(ids, predict_malicious(model, rows)))  # type: ignore[arg-type]


def alert_rows(alerts: list[Alert]) -> list[dict[str, Any]]:
    return [
        {
            "alert_id": alert.alert_id,
            "rule": alert.rule_id,
            "severity": alert.severity.value,
            "events": len(alert.event_ids),
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
        }
        for alert in alerts
    ]


def explain_alert(alert: Alert) -> dict[str, Any]:
    """Why an alert fired: rule, threshold, evidence, and the event ids it is based on."""
    return {
        "alert_id": alert.alert_id,
        "rule": alert.rule_id,
        "severity": alert.severity.value,
        "explanation": alert.explanation,
        "evidence": list(alert.evidence),
        "event_ids": list(alert.event_ids),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
    }


def related_events(events: EventDataset, alert: Alert) -> list[dict[str, Any]]:
    wanted = set(alert.event_ids)
    return [
        {
            "event_id": event.event_id,
            "timestamp_utc": event.timestamp_utc.isoformat(),
            "account_id": event.account_id,
            "source_ip": event.source_ip,
            "outcome": event.outcome.value,
            "country_code": event.country_code,
        }
        for event in events.events
        if event.event_id in wanted
    ]
