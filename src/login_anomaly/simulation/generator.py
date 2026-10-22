"""Deterministic generator of benign authentication traffic.

Semantics of ``GeneratorConfig``, as approved:

- ``n_accounts`` is the universe of synthetic accounts the generator may pick
  from. It is not a requirement that every account appears in the output.
- ``n_events`` is the exact number of events produced.
- Each event references one account from the universe.
- If ``n_events < n_accounts``, some accounts do not appear. This is valid.
- If ``n_events >= n_accounts``, the output is still not required to cover
  every account. Full coverage is not a property of benign traffic here.

Two public entry points, one implementation:

- ``generate(config)`` returns ``EventDataset``: events and manifest only. This
  is what detectors and investigators receive. It has no ground-truth field.
- ``generate_with_truth(config)`` returns ``GeneratedDataset``: events, ground
  truth, and manifest. Only the evaluation module should call it.

Both run the same private build, so for the same configuration their events
and manifests are identical.

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

Cost is linear in ``n_accounts + n_events``. The limits in ``config.py`` bound it.

Not yet protected: a golden digest of a fixed reference dataset. It is deferred
until the generator stabilizes. When added, any change to that digest must
come with a ``GENERATOR_VERSION`` bump in the same change.
"""

from __future__ import annotations

import ipaddress
import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta

from login_anomaly.events import ALLOWED_COUNTRY_CODES, AuthEvent, Outcome
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.ground_truth import GroundTruth, ScenarioLabel, ScenarioType
from login_anomaly.simulation.manifest import DatasetManifest, build_manifest
from login_anomaly.simulation.scenarios import (
    NOMINAL_RANGES,
    AccountProfile,
    CampaignCounter,
    Draft,
    ScenarioPlan,
    ScenarioRanges,
    bruteforce_drafts,
    decoy_drafts,
    spraying_drafts,
    traveler_drafts,
    travel_drafts,
)

BENIGN_SUCCESS_PROBABILITY = 0.95

# Source IPs for benign accounts come from 10.0.0.0/8, which is already on the
# synthetic allowlist in events.py.
_SOURCE_NETWORK_BASE = int(ipaddress.IPv4Address("10.0.0.0"))
_SOURCE_NETWORK_SIZE = 2**24

_COUNTRIES: tuple[str, ...] = tuple(sorted(ALLOWED_COUNTRY_CODES))


@dataclass(frozen=True)
class EventDataset:
    """Observable output only: what detectors and investigators may receive."""

    events: tuple[AuthEvent, ...]
    manifest: DatasetManifest


@dataclass(frozen=True)
class GeneratedDataset:
    """Events, ground truth, and provenance. For evaluation only.

    ``decoy_kinds`` maps the event id of each benign decoy to its kind. It is evaluation metadata,
    never a detector feature, and it is empty when no decoys were requested.
    """

    events: tuple[AuthEvent, ...]
    ground_truth: GroundTruth
    manifest: DatasetManifest
    decoy_kinds: Mapping[str, str] = field(default_factory=dict)


def generate(
    config: GeneratorConfig, plan: ScenarioPlan | None = None, ranges: ScenarioRanges | None = None
) -> EventDataset:
    """Generate exactly ``config.n_events`` events, without ground truth.

    Without a plan (or with an empty one) the output is benign only and unchanged
    from earlier versions. A non-empty plan adds malicious campaigns and decoys inside
    the same exact event budget. ``ranges`` selects the campaign parameters; the
    default is the nominal set, which matches the detector thresholds.
    """
    full = _build(config, plan, ranges)
    return EventDataset(events=full.events, manifest=full.manifest)


def generate_with_truth(
    config: GeneratorConfig, plan: ScenarioPlan | None = None, ranges: ScenarioRanges | None = None
) -> GeneratedDataset:
    """Generate the same events as ``generate`` plus their ground truth. Evaluation only."""
    return _build(config, plan, ranges)


def _build(config: GeneratorConfig, plan: ScenarioPlan | None, ranges: ScenarioRanges | None) -> GeneratedDataset:
    if plan is None or plan.is_empty():
        return _build_benign(config)
    return _build_mixed(config, plan, ranges or NOMINAL_RANGES)


def _build_mixed(config: GeneratorConfig, plan: ScenarioPlan, ranges: ScenarioRanges) -> GeneratedDataset:
    rng = random.Random(config.seed)
    account_width = len(str(config.n_accounts))
    profiles = [_draw_profile(rng, index, account_width) for index in range(config.n_accounts)]
    window_seconds = config.duration_hours * 3600
    start = config.start_utc

    counter = CampaignCounter()
    drafts: list[Draft] = []
    for _ in range(plan.bruteforce_campaigns):
        drafts += bruteforce_drafts(rng, start, window_seconds, profiles, counter, ranges)
    for _ in range(plan.password_spraying_campaigns):
        drafts += spraying_drafts(rng, start, window_seconds, profiles, counter, ranges)
    for _ in range(plan.impossible_travel_campaigns):
        drafts += travel_drafts(rng, start, window_seconds, profiles, counter, ranges)

    # Benign travelers come from accounts no attack uses, and they get no background traffic.
    # Any account an attack touched (bruteforce victim, spraying target, travel victim) is not a traveler.
    victim_ids = {draft.account_id for draft in drafts if draft.is_malicious}
    traveler_candidates = [profile for profile in profiles if profile.account_id not in victim_ids]
    if plan.benign_travelers > len(traveler_candidates):
        raise ValueError(
            f"benign_travelers={plan.benign_travelers} needs accounts that no attack uses; "
            f"only {len(traveler_candidates)} are available"
        )
    travelers = rng.sample(traveler_candidates, plan.benign_travelers)
    for traveler in travelers:
        drafts += traveler_drafts(rng, start, window_seconds, traveler)
    traveler_ids = {profile.account_id for profile in travelers}
    background = [profile for profile in profiles if profile.account_id not in traveler_ids]
    if not background:
        raise ValueError("no accounts left for background traffic after assigning benign travelers")
    # Decoys draw from the background pool, so travelers never get extra events.
    for index in range(plan.benign_decoys):
        drafts += decoy_drafts(rng, start, window_seconds, background, index)

    benign_count = config.n_events - len(drafts)
    if benign_count < 0:
        raise ValueError(
            f"scenario plan needs {len(drafts)} events but n_events is {config.n_events}"
        )
    for _ in range(benign_count):
        profile = background[rng.randrange(len(background))]
        offset = rng.randrange(window_seconds)
        succeeds = rng.random() < BENIGN_SUCCESS_PROBABILITY
        drafts.append(
            Draft(
                timestamp_utc=start + timedelta(seconds=offset),
                account_id=profile.account_id,
                source_ip=profile.source_ip,
                outcome=Outcome.SUCCESS if succeeds else Outcome.FAILURE,
                country_code=profile.country_code,
                scenario_type=ScenarioType.BENIGN,
                campaign_id=None,
                is_malicious=False,
            )
        )

    # Event ids come from a seeded permutation, not from the draft order. Otherwise the
    # campaign events, which are appended first, would get contiguous ids and leak their grouping.
    id_rng = random.Random(f"{config.seed}|event-ids")
    numbers = list(range(1, config.n_events + 1))
    id_rng.shuffle(numbers)
    event_width = len(str(config.n_events))
    events: list[AuthEvent] = []
    labels: list[ScenarioLabel] = []
    decoy_kinds: dict[str, str] = {}
    for draft, number in zip(drafts, numbers):
        event_id = f"evt-{number:0{event_width}d}"
        if draft.decoy_kind is not None:
            decoy_kinds[event_id] = draft.decoy_kind
        events.append(
            AuthEvent(
                event_id=event_id,
                timestamp_utc=draft.timestamp_utc,
                account_id=draft.account_id,
                source_ip=draft.source_ip,
                outcome=draft.outcome,
                country_code=draft.country_code,
            )
        )
        labels.append(
            ScenarioLabel(
                event_id=event_id,
                scenario_type=draft.scenario_type,
                campaign_id=draft.campaign_id,
                is_malicious=draft.is_malicious,
            )
        )
    events.sort(key=lambda event: (event.timestamp_utc, event.event_id))
    return GeneratedDataset(
        events=tuple(events),
        ground_truth=GroundTruth(labels),
        manifest=build_manifest(config, plan, ranges),
        decoy_kinds=decoy_kinds,
    )


def _build_benign(config: GeneratorConfig) -> GeneratedDataset:
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


def _draw_profile(rng: random.Random, index: int, width: int) -> AccountProfile:
    account_id = f"acct-{index + 1:0{width}d}"
    source_ip = str(ipaddress.IPv4Address(_SOURCE_NETWORK_BASE + rng.randrange(_SOURCE_NETWORK_SIZE)))
    country_code = _COUNTRIES[rng.randrange(len(_COUNTRIES))]
    return AccountProfile(account_id=account_id, source_ip=source_ip, country_code=country_code)
