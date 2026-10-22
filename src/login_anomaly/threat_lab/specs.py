"""Threat Lab: reproducible adversarial scenario definitions (no execution, no labels).

A ``ScenarioSpec`` says *what* to generate: seeds, a ``ScenarioPlan`` and ``ScenarioRanges``,
the only knobs the generator exposes. A ``ScenarioStrategy`` proposes specs. Running and
scoring a spec happens on the evaluation side (``evaluation/threat_lab.py``), the only place
that may touch ground truth.

Nothing here can change rules, features, models or evaluation sets: specs are frozen data,
and the runner refuses seeds reserved for training or for the reviewed evaluation sets.

Generator limits that bound what a strategy can express (verified, not worked around):
- Decoy kinds cannot be chosen. They rotate typo_burst, roaming, shared_nat by index, so
  decoy counts here are multiples of 3 and each kind appears equally often.
- Decoy, traveler and benign-background parameters are fixed constants in the generator.
- Only the three attack families in ``ScenarioRanges`` exist; no new attack types.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol

from login_anomaly.simulation.config import MAX_SEED
from login_anomaly.simulation.manifest import GENERATOR_VERSION
from login_anomaly.simulation.scenarios import DECOY_KINDS, HARD_RANGES, NOMINAL_RANGES, ScenarioPlan, ScenarioRanges
from login_anomaly.validation import require_int

# Threat Lab seeds. Disjoint from the training seeds (101-104) and the reviewed evaluation
# sets (201-303); the runner enforces that for any spec.
DEFAULT_SEEDS: tuple[int, ...] = (1001, 1002, 1003)
# Same campaign mix as the experiment's PLAN (kept equal by a test), so results are comparable.
BASE_PLAN = ScenarioPlan(bruteforce_campaigns=3, password_spraying_campaigns=2, impossible_travel_campaigns=3, benign_travelers=5)
_ID = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")


@dataclass(frozen=True)
class ScenarioSpec:
    """One reproducible adversarial scenario: identity, explicit parameters and seeds."""

    scenario_id: str
    strategy: str
    description: str
    seeds: tuple[int, ...]
    plan: ScenarioPlan
    ranges: ScenarioRanges = NOMINAL_RANGES
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or not _ID.match(self.scenario_id):
            raise ValueError("scenario_id must be lowercase letters, digits or '_', 1-64 chars")
        for name in ("strategy", "description"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.seeds, tuple) or not self.seeds:
            raise ValueError("seeds must be a non-empty tuple")
        for seed in self.seeds:
            require_int(seed, "seed", minimum=0, maximum=MAX_SEED)
        if len(set(self.seeds)) != len(self.seeds):
            raise ValueError("seeds must be unique")
        if not isinstance(self.plan, ScenarioPlan) or self.plan.is_empty():
            raise ValueError("plan must be a non-empty ScenarioPlan")
        if not isinstance(self.ranges, ScenarioRanges):
            raise ValueError("ranges must be a ScenarioRanges")
        if not isinstance(self.tags, tuple) or not all(isinstance(t, str) and t for t in self.tags):
            raise ValueError("tags must be a tuple of non-empty strings")

    def canonical_json(self) -> str:
        payload = {
            "scenario_id": self.scenario_id,
            "strategy": self.strategy,
            "seeds": list(self.seeds),
            "plan": json.loads(self.plan.canonical_json()),
            "ranges": json.loads(self.ranges.canonical_json()),
            "generator_version": GENERATOR_VERSION,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)

    def fingerprint(self) -> str:
        """SHA-256 of the parameters that determine the generated data. Description and tags excluded."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def metadata(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "strategy": self.strategy,
            "description": self.description,
            "tags": list(self.tags),
            "seeds": list(self.seeds),
            "plan": asdict(self.plan),
            "ranges": asdict(self.ranges),
            "ranges_are_nominal": self.ranges == NOMINAL_RANGES,
            "generator_version": GENERATOR_VERSION,
            "fingerprint": self.fingerprint(),
        }


class ScenarioStrategy(Protocol):
    """Proposes scenarios. Deterministic: the same seeds give the same specs.

    A future strategy (including an LLM-backed one) plugs in here and still only emits
    ``ScenarioSpec`` data; it never runs detectors or sees labels.
    """

    name: str

    def scenarios(self, seeds: tuple[int, ...]) -> tuple[ScenarioSpec, ...]: ...


@dataclass(frozen=True)
class NominalControl:
    """The nominal campaign mix without decoys. The reference every other scenario is read against."""

    name: str = "nominal_control"

    def scenarios(self, seeds: tuple[int, ...]) -> tuple[ScenarioSpec, ...]:
        return (
            ScenarioSpec("nominal_control", self.name, "Nominal campaigns, no decoys. Optimistic for rules by construction.", seeds, BASE_PLAN, tags=("control",)),
        )


@dataclass(frozen=True)
class DecoyPressure:
    """Benign look-alikes at increasing volume, with and without attacks. Probes false positives."""

    levels: tuple[int, ...] = (3, 6, 12)
    decoys_only_level: int | None = 6
    name: str = "decoy_pressure"

    def __post_init__(self) -> None:
        for level in (*self.levels, *(() if self.decoys_only_level is None else (self.decoys_only_level,))):
            require_int(level, "decoy level", minimum=len(DECOY_KINDS))
            if level % len(DECOY_KINDS):
                raise ValueError(f"decoy levels must be multiples of {len(DECOY_KINDS)} so every decoy kind appears equally")

    def scenarios(self, seeds: tuple[int, ...]) -> tuple[ScenarioSpec, ...]:
        specs = [
            ScenarioSpec(
                f"decoy_pressure_{level}", self.name,
                f"Nominal campaigns plus {level} benign decoys ({level // len(DECOY_KINDS)} of each kind).",
                seeds, replace(BASE_PLAN, benign_decoys=level), tags=("false_positives",),
            )
            for level in self.levels
        ]
        if self.decoys_only_level is not None:
            level = self.decoys_only_level
            specs.append(
                ScenarioSpec(
                    f"decoys_only_{level}", self.name,
                    f"{level} benign decoys and no attacks. Every flag is a false positive.",
                    seeds, ScenarioPlan(benign_decoys=level), tags=("false_positives", "no_attacks"),
                )
            )
        return tuple(specs)


# The fields of ScenarioRanges that belong to each attack family, and that family's plan field.
_FAMILIES: dict[str, tuple[tuple[str, ...], str]] = {
    "bruteforce": (("bruteforce_failures", "bruteforce_window_seconds"), "bruteforce_campaigns"),
    "password_spraying": (("spraying_accounts", "spraying_attempts_per_account", "spraying_window_seconds"), "password_spraying_campaigns"),
    "impossible_travel": (("travel_gap_seconds",), "impossible_travel_campaigns"),
}


@dataclass(frozen=True)
class BoundaryShift:
    """One attack family at a time, moved to ``shifted`` ranges (default: just outside the rule thresholds).

    Isolating a family shows which detector loses which attack, without the others mixed in.
    """

    shifted: ScenarioRanges = HARD_RANGES
    families: tuple[str, ...] = tuple(_FAMILIES)
    name: str = "boundary_shift"

    def __post_init__(self) -> None:
        unknown = set(self.families) - set(_FAMILIES)
        if unknown or not self.families:
            raise ValueError(f"families must be a non-empty subset of {sorted(_FAMILIES)}, got unknown {sorted(unknown)}")

    def scenarios(self, seeds: tuple[int, ...]) -> tuple[ScenarioSpec, ...]:
        specs = []
        for family in self.families:
            fields, plan_field = _FAMILIES[family]
            ranges = replace(NOMINAL_RANGES, **{name: getattr(self.shifted, name) for name in fields})
            plan = ScenarioPlan(**{plan_field: getattr(BASE_PLAN, plan_field)})
            specs.append(
                ScenarioSpec(
                    f"boundary_{family}", self.name,
                    f"Only {family} campaigns, with {', '.join(fields)} shifted; other families absent.",
                    seeds, plan, ranges, tags=("evasion", family),
                )
            )
        return tuple(specs)


@dataclass(frozen=True)
class BenignBehaviorShift:
    """More benign roaming and shared-address activity, with nominal attacks retained.

    This changes the benign feature distribution (country changes, new IPs and
    failures from a shared source), rather than merely changing random seeds.
    """

    benign_travelers: int = 25
    benign_decoys: int = 12
    name: str = "benign_behavior_shift"

    def __post_init__(self) -> None:
        require_int(self.benign_travelers, "benign_travelers", minimum=1, maximum=MAX_SEED)
        require_int(self.benign_decoys, "benign_decoys", minimum=len(DECOY_KINDS))
        if self.benign_decoys % len(DECOY_KINDS):
            raise ValueError(f"benign_decoys must be a multiple of {len(DECOY_KINDS)}")

    def scenarios(self, seeds: tuple[int, ...]) -> tuple[ScenarioSpec, ...]:
        return (
            ScenarioSpec(
                "benign_behavior_shift",
                self.name,
                "Nominal attacks with elevated benign multi-country travelers and shared-address decoys.",
                seeds,
                replace(BASE_PLAN, benign_travelers=self.benign_travelers, benign_decoys=self.benign_decoys),
                tags=("distribution_shift", "benign_roaming", "shared_address"),
            ),
        )


DEFAULT_STRATEGIES: tuple[ScenarioStrategy, ...] = (NominalControl(), DecoyPressure(), BoundaryShift(), BenignBehaviorShift())


def build_catalog(
    strategies: tuple[ScenarioStrategy, ...] = DEFAULT_STRATEGIES, seeds: tuple[int, ...] = DEFAULT_SEEDS
) -> tuple[ScenarioSpec, ...]:
    """All specs from the strategies, in order. Scenario ids must be unique across strategies."""
    specs = tuple(spec for strategy in strategies for spec in strategy.scenarios(seeds))
    ids = [spec.scenario_id for spec in specs]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate scenario ids: {duplicates}")
    return specs
