"""Malicious scenarios, benign decoys, and the plan and ranges that select them.

Each scenario produces observable drafts (events without ids) and the scenario
type of each one. The generator turns drafts into ``AuthEvent`` and
``ScenarioLabel`` objects, so labels come from the same objects as events.

Nominal signatures (``NOMINAL_RANGES``), from the events alone:

- bruteforce: one account, one source IP, 15 to 40 failures inside 10 minutes,
  optionally followed by one success.
- password_spraying: one source IP, 10 to 25 distinct accounts, 1 or 2 failures
  per account, all inside a 60 to 120 minute window.
- impossible_travel: a victim's home-country success, then a success from a
  different country 5 to 60 minutes later. Only the foreign success is malicious.

These nominal values are the same boundaries the rule detector uses. That makes
nominal results optimistic by construction. ``HARD_RANGES`` sits deliberately
outside those boundaries, so that the detector's misses can be measured. Nothing
tunes the detector to either set.

Benign decoys look partly like attacks without being attacks: a typo burst, a
roaming login, and a shared NAT address that the spraying rule flags (a known
false positive).
"""

from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from login_anomaly.events import ALLOWED_COUNTRY_CODES, Outcome
from login_anomaly.simulation.ground_truth import ScenarioType
from login_anomaly.validation import require_int

MAX_CAMPAIGNS = 1000
BRUTEFORCE_SUCCESS_PROBABILITY = 0.5
TRAVELER_GAP_SECONDS = (86400, 2 * 86400)
DECOY_KINDS: tuple[str, ...] = ("typo_burst", "roaming", "shared_nat")
DECOY_NAT_ACCOUNTS = (25, 40)

# Attacker and benign sources both come from 10.0.0.0/8. No separate range exists.
SOURCE_NETWORK_BASE = int(ipaddress.IPv4Address("10.0.0.0"))
SOURCE_NETWORK_SIZE = 2**24

COUNTRIES: tuple[str, ...] = tuple(sorted(ALLOWED_COUNTRY_CODES))


@dataclass(frozen=True)
class ScenarioRanges:
    """Parameter ranges for the malicious scenarios. Bounds are inclusive."""

    bruteforce_failures: tuple[int, int] = (15, 40)
    bruteforce_window_seconds: int = 600
    spraying_accounts: tuple[int, int] = (10, 25)
    spraying_attempts_per_account: tuple[int, int] = (1, 2)
    spraying_window_seconds: tuple[int, int] = (3600, 7200)
    travel_gap_seconds: tuple[int, int] = (300, 3600)

    def __post_init__(self) -> None:
        for name in ("bruteforce_failures", "spraying_accounts", "spraying_attempts_per_account", "spraying_window_seconds", "travel_gap_seconds"):
            low, high = getattr(self, name)
            require_int(low, f"{name}[0]", minimum=1)
            require_int(high, f"{name}[1]", minimum=1)
            if low > high:
                raise ValueError(f"{name} must have low <= high, got {(low, high)}")
        require_int(self.bruteforce_window_seconds, "bruteforce_window_seconds", minimum=1)

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False)


NOMINAL_RANGES = ScenarioRanges()
HARD_RANGES = ScenarioRanges(
    bruteforce_failures=(8, 14),
    bruteforce_window_seconds=1500,
    spraying_accounts=(5, 9),
    spraying_attempts_per_account=(2, 3),
    spraying_window_seconds=(10800, 14400),
    travel_gap_seconds=(3660, 10800),
)


@dataclass(frozen=True)
class ScenarioPlan:
    """How many campaigns and decoys to generate. All zero means benign only."""

    bruteforce_campaigns: int = 0
    password_spraying_campaigns: int = 0
    impossible_travel_campaigns: int = 0
    benign_travelers: int = 0
    benign_decoys: int = 0

    def __post_init__(self) -> None:
        for name in ("bruteforce_campaigns", "password_spraying_campaigns", "impossible_travel_campaigns", "benign_travelers", "benign_decoys"):
            require_int(getattr(self, name), name, minimum=0, maximum=MAX_CAMPAIGNS)

    def is_empty(self) -> bool:
        return self == ScenarioPlan()

    def canonical_json(self) -> str:
        payload = asdict(self)
        # Omit decoys when zero, so plans written before decoys existed keep their hash.
        if payload["benign_decoys"] == 0:
            del payload["benign_decoys"]
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class AccountProfile:
    account_id: str
    source_ip: str
    country_code: str


@dataclass(frozen=True)
class Draft:
    """An event before its id is assigned. ``campaign_id`` is None for benign drafts."""

    timestamp_utc: datetime
    account_id: str
    source_ip: str
    outcome: Outcome
    country_code: str
    scenario_type: ScenarioType
    campaign_id: str | None
    is_malicious: bool
    decoy_kind: str | None = None


@dataclass
class CampaignCounter:
    """Campaign numbering per scenario, starting at 1 and advancing only when used."""

    by_code: dict[str, int] = field(default_factory=dict)

    def next_id(self, code: str) -> str:
        self.by_code[code] = self.by_code.get(code, 0) + 1
        return f"camp-{code}-{self.by_code[code]:04d}"


def source_ip_from_pool(rng: random.Random) -> str:
    return str(ipaddress.IPv4Address(SOURCE_NETWORK_BASE + rng.randrange(SOURCE_NETWORK_SIZE)))


def require_window(window_seconds: int, needed: int, scenario: str) -> None:
    if window_seconds < needed:
        raise ValueError(f"window too short for {scenario}: needs {needed} seconds, has {window_seconds}")


def bruteforce_drafts(
    rng: random.Random,
    start: datetime,
    window_seconds: int,
    profiles: list[AccountProfile],
    counter: CampaignCounter,
    ranges: ScenarioRanges = NOMINAL_RANGES,
) -> list[Draft]:
    span = ranges.bruteforce_window_seconds
    require_window(window_seconds, span, "bruteforce")
    victim = profiles[rng.randrange(len(profiles))]
    source = source_ip_from_pool(rng)
    failures = rng.randint(*ranges.bruteforce_failures)
    succeeds = rng.random() < BRUTEFORCE_SUCCESS_PROBABILITY
    count = failures + (1 if succeeds else 0)
    base = rng.randrange(window_seconds - span + 1)
    offsets = sorted(base + rng.randrange(span) for _ in range(count))
    campaign = counter.next_id("bf")
    drafts = []
    for index, offset in enumerate(offsets):
        last_and_success = succeeds and index == count - 1
        drafts.append(
            Draft(
                timestamp_utc=start + timedelta(seconds=offset),
                account_id=victim.account_id,
                source_ip=source,
                outcome=Outcome.SUCCESS if last_and_success else Outcome.FAILURE,
                country_code=victim.country_code,
                scenario_type=ScenarioType.BRUTEFORCE,
                campaign_id=campaign,
                is_malicious=True,
            )
        )
    return drafts


def spraying_drafts(
    rng: random.Random,
    start: datetime,
    window_seconds: int,
    profiles: list[AccountProfile],
    counter: CampaignCounter,
    ranges: ScenarioRanges = NOMINAL_RANGES,
) -> list[Draft]:
    targets_count = rng.randint(*ranges.spraying_accounts)
    if targets_count > len(profiles):
        raise ValueError(
            f"password_spraying needs {targets_count} accounts but n_accounts is {len(profiles)}"
        )
    require_window(window_seconds, ranges.spraying_window_seconds[1], "password_spraying")
    targets = rng.sample(profiles, targets_count)
    source = source_ip_from_pool(rng)
    span = rng.randint(*ranges.spraying_window_seconds)
    base = rng.randrange(window_seconds - span + 1)
    campaign = counter.next_id("sp")
    drafts = []
    for target in targets:
        for _ in range(rng.randint(*ranges.spraying_attempts_per_account)):
            drafts.append(
                Draft(
                    timestamp_utc=start + timedelta(seconds=base + rng.randrange(span)),
                    account_id=target.account_id,
                    source_ip=source,
                    outcome=Outcome.FAILURE,
                    country_code=target.country_code,
                    scenario_type=ScenarioType.PASSWORD_SPRAYING,
                    campaign_id=campaign,
                    is_malicious=True,
                )
            )
    return drafts


def travel_drafts(
    rng: random.Random,
    start: datetime,
    window_seconds: int,
    profiles: list[AccountProfile],
    counter: CampaignCounter,
    ranges: ScenarioRanges = NOMINAL_RANGES,
) -> list[Draft]:
    max_gap = ranges.travel_gap_seconds[1]
    require_window(window_seconds, max_gap + 1, "impossible_travel")
    victim = profiles[rng.randrange(len(profiles))]
    foreign = rng.choice([country for country in COUNTRIES if country != victim.country_code])
    home_offset = rng.randrange(window_seconds - max_gap)
    gap = rng.randint(*ranges.travel_gap_seconds)
    home = Draft(
        timestamp_utc=start + timedelta(seconds=home_offset),
        account_id=victim.account_id,
        source_ip=victim.source_ip,
        outcome=Outcome.SUCCESS,
        country_code=victim.country_code,
        scenario_type=ScenarioType.BENIGN,
        campaign_id=None,
        is_malicious=False,
    )
    attack = Draft(
        timestamp_utc=start + timedelta(seconds=home_offset + gap),
        account_id=victim.account_id,
        source_ip=source_ip_from_pool(rng),
        outcome=Outcome.SUCCESS,
        country_code=foreign,
        scenario_type=ScenarioType.IMPOSSIBLE_TRAVEL,
        campaign_id=counter.next_id("it"),
        is_malicious=True,
    )
    return [home, attack]


def traveler_drafts(rng: random.Random, start: datetime, window_seconds: int, account: AccountProfile) -> list[Draft]:
    # The account is chosen by the caller, who guarantees it is used by no other scenario
    # and receives no background traffic. Otherwise its country changes could fall
    # inside a short window and look like travel.
    require_window(window_seconds, TRAVELER_GAP_SECONDS[1] + 1, "benign travelers")
    foreign = rng.choice([country for country in COUNTRIES if country != account.country_code])
    first_offset = rng.randrange(window_seconds - TRAVELER_GAP_SECONDS[1])
    second_offset = first_offset + rng.randint(*TRAVELER_GAP_SECONDS)
    return [
        Draft(
            timestamp_utc=start + timedelta(seconds=offset),
            account_id=account.account_id,
            source_ip=account.source_ip,
            outcome=Outcome.SUCCESS,
            country_code=country,
            scenario_type=ScenarioType.BENIGN,
            campaign_id=None,
            is_malicious=False,
        )
        for offset, country in ((first_offset, account.country_code), (second_offset, foreign))
    ]


def decoy_drafts(
    rng: random.Random, start: datetime, window_seconds: int, profiles: list[AccountProfile], index: int
) -> list[Draft]:
    """One benign decoy episode. Kinds rotate in DECOY_KINDS order, so the mix is fixed by ``index``.

    Ranges come from everyday benign behaviour, not from the rule thresholds:

    - typo_burst: a user mistypes a password two to six times within about two minutes, then gets in.
    - roaming: a user logs in from home, then from another country four to twelve hours later
      (a trip). The travel rule must not fire on it.
    - shared_nat: a shared office or campus address where 25 to 40 people each fail once within an hour,
      for example after a password-expiry notice. The spraying rule fires on this: a known false positive.

    Assumption, not validated: these behaviours and their frequencies are what the team expects,
    not measured from real logs.
    """
    kind = DECOY_KINDS[index % len(DECOY_KINDS)]
    if kind == "typo_burst":
        require_window(window_seconds, 120, "decoy typo_burst")
        user = profiles[rng.randrange(len(profiles))]
        base = rng.randrange(window_seconds - 120 + 1)
        count = rng.randint(2, 6)
        offsets = sorted(base + rng.randrange(120) for _ in range(count + 1))
        return [
            Draft(
                timestamp_utc=start + timedelta(seconds=offset),
                account_id=user.account_id,
                source_ip=user.source_ip,
                outcome=Outcome.SUCCESS if position == count else Outcome.FAILURE,
                country_code=user.country_code,
                scenario_type=ScenarioType.BENIGN,
                campaign_id=None,
                is_malicious=False,
                decoy_kind=kind,
            )
            for position, offset in enumerate(offsets)
        ]
    if kind == "roaming":
        max_gap = 43200  # 12 hours
        require_window(window_seconds, max_gap + 1, "decoy roaming")
        user = profiles[rng.randrange(len(profiles))]
        foreign = rng.choice([country for country in COUNTRIES if country != user.country_code])
        home_offset = rng.randrange(window_seconds - max_gap)
        far_offset = home_offset + rng.randint(14400, max_gap)  # 4 to 12 hours
        return [
            Draft(
                timestamp_utc=start + timedelta(seconds=offset),
                account_id=user.account_id,
                source_ip=user.source_ip,
                outcome=Outcome.SUCCESS,
                country_code=country,
                scenario_type=ScenarioType.BENIGN,
                campaign_id=None,
                is_malicious=False,
                decoy_kind=kind,
            )
            for offset, country in ((home_offset, user.country_code), (far_offset, foreign))
        ]
    require_window(window_seconds, 3600, "decoy shared_nat")
    low, high = DECOY_NAT_ACCOUNTS
    count = rng.randint(low, high)
    if count > len(profiles):
        raise ValueError(f"shared_nat decoy needs {count} accounts but n_accounts is {len(profiles)}")
    source = source_ip_from_pool(rng)
    base = rng.randrange(window_seconds - 3600 + 1)
    users = rng.sample(profiles, count)
    return [
        Draft(
            timestamp_utc=start + timedelta(seconds=base + rng.randrange(3600)),
            account_id=user.account_id,
            source_ip=source,
            outcome=Outcome.FAILURE,
            country_code=user.country_code,
            scenario_type=ScenarioType.BENIGN,
            campaign_id=None,
            is_malicious=False,
            decoy_kind=kind,
        )
        for user in users
    ]
