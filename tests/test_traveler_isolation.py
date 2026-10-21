"""Benign travelers keep exactly their two traveler events and receive no decoy or background events.

Regression test for a bug: decoys drew accounts from all profiles, so travelers got extra events.
"""

from datetime import datetime, timezone

import pytest

import login_anomaly.simulation.generator as generator
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import generate
from login_anomaly.simulation.scenarios import ScenarioPlan

UTC = timezone.utc
PLAN = ScenarioPlan(bruteforce_campaigns=2, password_spraying_campaigns=1, impossible_travel_campaigns=2, benign_travelers=5, benign_decoys=9)


@pytest.mark.parametrize("seed", range(1, 11))
def test_travelers_have_exactly_their_two_events(seed: int, monkeypatch: pytest.MonkeyPatch) -> None:
    travelers: list[str] = []
    original = generator.traveler_drafts

    def record(rng, start, window_seconds, account):  # type: ignore[no-untyped-def]
        travelers.append(account.account_id)
        return original(rng, start, window_seconds, account)

    monkeypatch.setattr(generator, "traveler_drafts", record)
    config = GeneratorConfig(seed, datetime(2026, 1, 1, tzinfo=UTC), 72, 200, 3000)
    events = generate(config, PLAN).events

    assert len(travelers) == 5
    for account in travelers:
        own = [e for e in events if e.account_id == account]
        assert len(own) == 2, f"seed {seed}: traveler {account} has {len(own)} events"
        assert own[0].country_code != own[1].country_code
