"""Deterministic generator of benign authentication traffic.

Semantics of ``GeneratorConfig``, as approved:

- ``n_accounts`` is the universe of synthetic accounts the generator may pick
  from. It is not a requirement that every account appears in the output.
- ``n_events`` is the exact number of events produced.
- Each event references one account from the universe.
- If ``n_events < n_accounts``, some accounts do not appear. This is valid.
- If ``n_events >= n_accounts``, the output is still not required to cover
  every account. Full coverage is not a property of benign traffic here.

Reproducibility:

- All randomness comes from one local ``random.Random(config.seed)``. The
  global random state, the wall clock, and UUID or OS entropy are never used.
- Draws happen in a fixed order: first the profile of every account, then one
  block per event. Output therefore depends only on the configuration.
- Event IDs are derived from the event's generation index, so they are unique
  and reproducible. Events are returned sorted by ``(timestamp_utc, event_id)``.

Each account has a fixed source IP and country for the whole dataset. Benign
traffic is generated with a fixed success probability. Both values are
constants or per-account profile draws, not sources of hidden state.

Cost is linear in ``n_accounts + n_events``. Very large universes are slow.

Not yet protected: a golden digest of a fixed reference dataset. It is deferred
until the generator stabilizes. When added, any change to that digest must
come with a ``GENERATOR_VERSION`` bump in the same change.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from datetime import timedelta

from login_anomaly.events import ALLOWED_COUNTRY_CODES, AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.ground_truth import GroundTruth, ScenarioLabel, ScenarioType
from login_anomaly.simulation.manifest import DatasetManifest, build_manifest

BENIGN_SUCCESS_PROBABILITY = 0.95

# Source IPs for benign accounts come from 10.0.0.0/8, which is already on the
# synthetic allowlist in events.py.
_SOURCE_NETWORK_BASE = int(ipaddress.IPv4Address("10.0.0.0"))
_SOURCE_NETWORK_SIZE = 2**24

_COUNTRIES: tuple[str, ...] = tuple(sorted(ALLOWED_COUNTRY_CODES))


@dataclass(frozen=True)
class GeneratedDataset:
    """Events (observable), ground truth (evaluation only), and provenance."""

    events: tuple[AuthEvent, ...]
    ground_truth: GroundTruth
    manifest: DatasetManifest


@dataclass(frozen=True)
class _AccountProfile:
    account_id: str
    source_ip: str
    country_code: str


def generate(config: GeneratorConfig) -> GeneratedDataset:
    """Generate exactly ``config.n_events`` benign events. See module docs for semantics."""
    rng = random.Random(config.seed)
    account_width = len(str(config.n_accounts))
    profiles = [_draw_profile(rng, index, account_width) for index in range(config.n_accounts)]

    event_width = len(str(config.n_events))
    window_seconds = config.duration_hours * 3600
    events: list[AuthEvent] = []
    labels: list[ScenarioLabel] = []
    for index in range(config.n_events):
        profile = profiles[rng.randrange(config.n_accounts)]
        offset = rng.randrange(window_seconds)
        outcome = Outcome.SUCCESS if rng.random() < BENIGN_SUCCESS_PROBABILITY else Outcome.FAILURE
        event_id = f"evt-{index + 1:0{event_width}d}"
        events.append(
            AuthEvent(
                event_id=event_id,
                timestamp_utc=config.start_utc + timedelta(seconds=offset),
                account_id=profile.account_id,
                source_ip=profile.source_ip,
                outcome=outcome,
                country_code=profile.country_code,
            )
        )
        labels.append(
            ScenarioLabel(
                event_id=event_id,
                scenario_type=ScenarioType.BENIGN,
                campaign_id=None,
                is_malicious=False,
            )
        )

    events.sort(key=lambda event: (event.timestamp_utc, event.event_id))
    return GeneratedDataset(
        events=tuple(events),
        ground_truth=GroundTruth(labels),
        manifest=build_manifest(config),
    )


def _draw_profile(rng: random.Random, index: int, width: int) -> _AccountProfile:
    account_id = f"acct-{index + 1:0{width}d}"
    source_ip = str(ipaddress.IPv4Address(_SOURCE_NETWORK_BASE + rng.randrange(_SOURCE_NETWORK_SIZE)))
    country_code = _COUNTRIES[rng.randrange(len(_COUNTRIES))]
    return _AccountProfile(account_id=account_id, source_ip=source_ip, country_code=country_code)
