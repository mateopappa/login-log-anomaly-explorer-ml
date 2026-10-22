"""Shifted campaigns and benign decoys: evaluation scenarios that do not share the detector's thresholds.

The nominal scenarios (default ScenarioRanges) are unchanged and still match the
detector thresholds by design. The shifted ranges deliberately sit outside them, so
that the detector's misses are measurable. Nothing here tunes the detector.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from login_anomaly.detection.rules import detect
from login_anomaly.events import Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate, generate_with_truth
from login_anomaly.simulation.ground_truth import ScenarioType
from login_anomaly.simulation.manifest import build_manifest
from login_anomaly.simulation.scenarios import HARD_RANGES, NOMINAL_RANGES, ScenarioPlan, ScenarioRanges

UTC = timezone.utc


def config(seed: int = 5, n_events: int = 3000, n_accounts: int = 200, duration_hours: int = 72) -> GeneratorConfig:
    return GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, tzinfo=UTC),
        duration_hours=duration_hours,
        n_accounts=n_accounts,
        n_events=n_events,
    )


PLAN = ScenarioPlan(bruteforce_campaigns=3, password_spraying_campaigns=2, impossible_travel_campaigns=3, benign_travelers=2)


# --- compatibility of the nominal path ---


def test_nominal_ranges_reproduce_the_default_generation() -> None:
    assert generate(config(), PLAN).events == generate(config(), PLAN, ranges=NOMINAL_RANGES).events


def test_canonical_plan_json_is_unchanged_when_no_decoys_are_requested() -> None:
    # Keys are sorted, so "benign_travelers" comes before "bruteforce_campaigns".
    assert ScenarioPlan(bruteforce_campaigns=2).canonical_json() == (
        '{"benign_travelers":0,"bruteforce_campaigns":2,'
        '"impossible_travel_campaigns":0,"password_spraying_campaigns":0}'
    )


def test_ranges_validation_rejects_inverted_bounds() -> None:
    with pytest.raises(ValueError, match="bruteforce_failures"):
        ScenarioRanges(bruteforce_failures=(40, 15))


def test_plan_rejects_negative_decoys() -> None:
    with pytest.raises(ValueError, match="benign_decoys"):
        ScenarioPlan(benign_decoys=-1)


# --- shifted campaigns sit outside the detector's thresholds ---


def test_shifted_campaigns_produce_no_rule_alerts() -> None:
    dataset = generate(config(), ScenarioPlan(bruteforce_campaigns=4, password_spraying_campaigns=3, impossible_travel_campaigns=4), ranges=HARD_RANGES)
    assert detect(list(dataset.events)) == []


def test_shifted_bruteforce_never_reaches_15_failures_in_10_minutes() -> None:
    dataset = generate_with_truth(config(), ScenarioPlan(bruteforce_campaigns=6), ranges=HARD_RANGES)
    by_campaign: dict[str, list] = {}
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        if label.scenario_type is ScenarioType.BRUTEFORCE:
            by_campaign.setdefault(label.campaign_id or "", []).append(event)
    assert len(by_campaign) == 6
    for events in by_campaign.values():
        stamps = sorted(e.timestamp_utc for e in events)
        densest = max(
            sum(1 for other in stamps if start <= other <= start + timedelta(minutes=10))
            for start in stamps
        )
        assert densest < 15


def test_shifted_travel_is_caught_only_through_background_neighbours() -> None:
    # The campaign's own home login is more than 60 minutes before the foreign login, so the rule
    # never pairs those two. A shifted campaign can still be flagged when a benign login of the
    # same victim falls within 60 minutes before the foreign login. That is a real mechanism of
    # the rule, so it is asserted here rather than hidden. Its size is reported by the experiment.
    dataset = generate_with_truth(config(), ScenarioPlan(impossible_travel_campaigns=5), ranges=HARD_RANGES)
    by_id = {e.event_id: e for e in dataset.events}
    attacks = {
        e.event_id
        for e in dataset.events
        if dataset.ground_truth.label_for(e.event_id).scenario_type is ScenarioType.IMPOSSIBLE_TRAVEL
    }
    assert len(attacks) == 5
    for alert in detect(list(dataset.events)):
        if alert.rule_id != "impossible_travel":
            continue
        attack_ids = set(alert.event_ids) & attacks
        if not attack_ids:
            continue
        (attack_id,) = attack_ids
        (partner_id,) = set(alert.event_ids) - attack_ids
        partner = by_id[partner_id]
        assert not dataset.ground_truth.label_for(partner_id).is_malicious
        assert partner.account_id == by_id[attack_id].account_id


def test_shifted_dataset_keeps_the_exact_event_budget() -> None:
    assert len(generate(config(n_events=1200), ScenarioPlan(bruteforce_campaigns=3), ranges=HARD_RANGES).events) == 1200


# --- benign decoys ---


def test_decoys_are_benign_and_add_no_malicious_labels() -> None:
    dataset = generate_with_truth(config(), ScenarioPlan(benign_decoys=6))
    assert not any(dataset.ground_truth.label_for(e.event_id).is_malicious for e in dataset.events)
    assert len(dataset.events) == 3000


def test_typo_burst_and_roaming_decoys_do_not_alert() -> None:
    # Decoy kinds are assigned in order: typo burst, roaming, shared NAT. Two decoys cover the first two.
    assert detect(list(generate(config(), ScenarioPlan(benign_decoys=2)).events)) == []


def test_shared_nat_decoy_is_a_known_spraying_false_positive() -> None:
    # Twelve accounts behind one shared address look like spraying to the rule. This is intended:
    # it is a documented false positive that the evaluation should count, not hide.
    dataset = generate_with_truth(config(), ScenarioPlan(benign_decoys=3))
    spraying = [a for a in detect(list(dataset.events)) if a.rule_id == "password_spraying"]
    assert spraying
    for alert in spraying:
        assert all(not dataset.ground_truth.label_for(event_id).is_malicious for event_id in alert.event_ids)


# --- provenance ---


def test_manifest_records_non_nominal_ranges() -> None:
    cfg = config()
    nominal = build_manifest(cfg, PLAN)
    shifted = build_manifest(cfg, PLAN, HARD_RANGES)
    assert nominal.scenario_plan_sha256 != shifted.scenario_plan_sha256
    assert build_manifest(cfg, PLAN, NOMINAL_RANGES) == nominal


def test_ranges_serialize_deterministically() -> None:
    assert json.loads(HARD_RANGES.canonical_json())["bruteforce_failures"] == [8, 14]
