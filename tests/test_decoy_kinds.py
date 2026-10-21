"""Decoy kinds: recorded for evaluation only, and their ranges sit away from the rule thresholds."""

from datetime import datetime, timedelta, timezone

from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate, generate_with_truth
from login_anomaly.simulation.scenarios import ScenarioPlan

UTC = timezone.utc
CONFIG = GeneratorConfig(9, datetime(2026, 1, 1, tzinfo=UTC), 72, 200, 3000)


def test_decoy_kinds_are_recorded_for_evaluation_only() -> None:
    dataset = generate_with_truth(CONFIG, ScenarioPlan(benign_decoys=6))
    assert set(dataset.decoy_kinds.values()) == {"typo_burst", "roaming", "shared_nat"}
    assert set(dataset.decoy_kinds) <= {e.event_id for e in dataset.events}
    assert not any(dataset.ground_truth.label_for(eid).is_malicious for eid in dataset.decoy_kinds)


def test_detector_facing_generate_carries_no_decoy_kinds() -> None:
    assert not hasattr(generate(CONFIG, ScenarioPlan(benign_decoys=6)), "decoy_kinds")


def test_no_decoys_means_no_decoy_kinds() -> None:
    assert generate_with_truth(CONFIG, ScenarioPlan(bruteforce_campaigns=1)).decoy_kinds == {}


def test_roaming_gap_is_far_above_the_travel_threshold() -> None:
    # Travel threshold is 60 minutes. Roaming decoys are 4 to 12 hours, a plausible trip.
    dataset = generate_with_truth(CONFIG, ScenarioPlan(benign_decoys=2))
    roaming = [e for e in dataset.events if dataset.decoy_kinds.get(e.event_id) == "roaming"]
    assert len(roaming) == 2
    gap = max(e.timestamp_utc for e in roaming) - min(e.timestamp_utc for e in roaming)
    assert timedelta(hours=4) <= gap <= timedelta(hours=12)


def test_typo_burst_stays_well_below_the_bruteforce_threshold() -> None:
    # Bruteforce threshold is 15 failures. A typo burst is 2 to 6 mistakes.
    dataset = generate_with_truth(CONFIG, ScenarioPlan(benign_decoys=1))
    failures = [
        e for e in dataset.events
        if dataset.decoy_kinds.get(e.event_id) == "typo_burst" and e.outcome.value == "failure"
    ]
    assert 2 <= len(failures) <= 6
