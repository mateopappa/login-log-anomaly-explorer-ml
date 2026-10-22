"""Dashboard logic and the evaluation panel. The Streamlit app itself is not imported here."""

from login_anomaly.dashboard.view import (
    SessionConfig,
    alert_rows,
    catalog_rows,
    events_for,
    explain_alert,
    related_events,
    rule_alerts,
    scenario_detail,
)
from login_anomaly.evaluation.panel import comparison_rows, truth_for
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.threat_lab.specs import build_catalog

PLAN = ScenarioPlan(bruteforce_campaigns=2, password_spraying_campaigns=1, impossible_travel_campaigns=2, benign_travelers=2)
SESSION = SessionConfig(seed=31, n_events=1500, n_accounts=150, duration_hours=72, plan=PLAN)


def test_events_for_returns_events_and_manifest_only() -> None:
    dataset = events_for(SESSION)
    assert not hasattr(dataset, "ground_truth")
    assert len(dataset.events) == 1500


def test_detection_view_and_evaluation_panel_share_the_same_events() -> None:
    assert events_for(SESSION).events == truth_for(
        SESSION.seed, SESSION.n_events, SESSION.n_accounts, SESSION.duration_hours, PLAN
    ).events


def test_rule_alerts_rows_and_explanations_are_structured() -> None:
    dataset = events_for(SESSION)
    alerts = rule_alerts(dataset)
    assert alerts, "the plan should produce at least one alert"
    rows = alert_rows(alerts)
    assert {"alert_id", "rule", "severity", "events", "first_seen", "last_seen"} <= set(rows[0])
    explanation = explain_alert(alerts[0])
    assert explanation["explanation"] and explanation["evidence"]
    assert explanation["event_ids"] == [e for e in alerts[0].event_ids]


def test_related_events_are_exactly_the_alert_events() -> None:
    dataset = events_for(SESSION)
    alert = rule_alerts(dataset)[0]
    related = related_events(dataset, alert)
    assert {row["event_id"] for row in related} == set(alert.event_ids)


def test_comparison_rows_report_each_method_against_labels() -> None:
    truth = truth_for(SESSION.seed, SESSION.n_events, SESSION.n_accounts, SESSION.duration_hours, PLAN)
    flagged_ids = {event_id for alert in rule_alerts(events_for(SESSION)) for event_id in alert.event_ids}
    rows = comparison_rows(truth, {"rules": flagged_ids, "nothing": set()})
    by_method = {row["method"]: row for row in rows}
    assert by_method["nothing"]["tp"] == 0 and by_method["nothing"]["recall"] == 0.0
    total = by_method["rules"]["tp"] + by_method["rules"]["fn"]
    assert total == sum(1 for e in truth.events if truth.ground_truth.label_for(e.event_id).is_malicious)


def test_comparison_rows_on_hand_built_truth() -> None:
    from login_anomaly.simulation.generator import GeneratedDataset
    from login_anomaly.simulation.ground_truth import GroundTruth, ScenarioLabel, ScenarioType
    from login_anomaly.simulation.manifest import build_manifest
    from login_anomaly.simulation.config import GeneratorConfig
    from login_anomaly.events import AuthEvent, Outcome
    from datetime import datetime, timezone

    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = tuple(
        AuthEvent(f"evt-{i}", t, "acct-1", "10.0.0.1", Outcome.SUCCESS, "AR") for i in range(1, 5)
    )
    labels = [
        ScenarioLabel("evt-1", ScenarioType.BRUTEFORCE, "camp-bf-0001", True),
        ScenarioLabel("evt-2", ScenarioType.BRUTEFORCE, "camp-bf-0001", True),
        ScenarioLabel("evt-3", ScenarioType.BENIGN, None, False),
        ScenarioLabel("evt-4", ScenarioType.BENIGN, None, False),
    ]
    config = GeneratorConfig(1, t, 1, 1, 4)
    truth = GeneratedDataset(events=events, ground_truth=GroundTruth(labels), manifest=build_manifest(config))
    (row,) = comparison_rows(truth, {"m": {"evt-1", "evt-3"}})
    assert (row["tp"], row["fp"], row["fn"], row["tn"]) == (1, 1, 1, 1)
    assert row["precision"] == 0.5 and row["recall"] == 0.5


def test_catalog_rows_list_every_scenario_with_its_seeds_and_range_kind() -> None:
    specs = build_catalog()
    rows = catalog_rows(specs)
    assert [row["scenario_id"] for row in rows] == [spec.scenario_id for spec in specs]
    by_id = {row["scenario_id"]: row for row in rows}
    assert by_id["nominal_control"]["ranges"] == "nominal"
    assert by_id["boundary_bruteforce"]["ranges"] == "shifted"
    assert by_id["nominal_control"]["campaigns"] == "bruteforce_campaigns=3, password_spraying_campaigns=2, impossible_travel_campaigns=3, benign_travelers=5"


def test_scenario_detail_pairs_each_seed_with_its_f1_and_lists_false_positive_alerts() -> None:
    item = {
        "scenario": {"seeds": [1001, 1002]},
        "methods": [
            {"method": "all_benign", "f1_per_seed": [0.0, 0.0]},
            {"method": "rules", "f1_per_seed": [0.5, 0.75]},
            {"method": "ml", "f1_per_seed": [0.9, 0.8]},
        ],
        "alerts_without_malicious_events_by_rule_and_decoy": {"password_spraying/shared_nat": 2},
    }
    detail = scenario_detail(item)
    assert {"method": "rules", "seed": 1002, "f1": 0.75} in detail["per_seed"]
    assert all(row["method"] != "all_benign" for row in detail["per_seed"])
    assert detail["false_positive_alerts"] == [{"rule / decoy kind": "password_spraying/shared_nat", "false positive alerts": 2}]
