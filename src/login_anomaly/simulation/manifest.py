"""Dataset provenance: what produced a generated dataset.

The manifest records only the seed, the two versions, and a hash of the
configuration. It holds no run timestamp, host name, or other metadata that
would make two identical runs differ.

``canonical_config_hash`` covers the configuration fields only. It does not
detect changes to generator code. That is what ``GENERATOR_VERSION`` is for,
and a generator change must bump it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from login_anomaly.events import SCHEMA_VERSION
from login_anomaly.simulation.config import GeneratorConfig, validate_seed
from login_anomaly.simulation.scenarios import NOMINAL_RANGES, ScenarioPlan, ScenarioRanges
from login_anomaly.validation import require_non_empty_str

# 0.2.0: the generator gained scenario plans. Benign-only output is unchanged,
# but the manifest now records the plan, so the version moves.
GENERATOR_VERSION = "0.2.0"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def scenario_plan_sha256(plan: ScenarioPlan, ranges: ScenarioRanges | None = None) -> str:
    """Hash of the plan. Non-nominal ranges are part of the hash, so a shifted dataset is never mistaken for a nominal one.

    With nominal ranges (or none) the hash is that of the plan alone, so existing manifests are unchanged.
    """
    text = plan.canonical_json()
    if ranges is not None and ranges != NOMINAL_RANGES:
        text += "|ranges:" + ranges.canonical_json()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_EMPTY_PLAN_SHA256 = scenario_plan_sha256(ScenarioPlan())


def canonical_config_json(config: GeneratorConfig) -> str:
    """Deterministic JSON for a config: sorted keys, no whitespace, ISO 8601 UTC."""
    payload = {
        "seed": config.seed,
        "start_utc": config.start_utc.isoformat(),
        "duration_hours": config.duration_hours,
        "n_accounts": config.n_accounts,
        "n_events": config.n_events,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_config_hash(config: GeneratorConfig) -> str:
    return hashlib.sha256(canonical_config_json(config).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DatasetManifest:
    seed: int
    schema_version: str
    generator_version: str
    config_sha256: str
    scenario_plan_sha256: str = _EMPTY_PLAN_SHA256

    def __post_init__(self) -> None:
        # Same seed rule as GeneratorConfig, so the manifest never accepts a seed the config rejects.
        validate_seed(self.seed)
        require_non_empty_str(self.schema_version, "schema_version")
        require_non_empty_str(self.generator_version, "generator_version")
        if not isinstance(self.config_sha256, str) or not _SHA256_HEX.fullmatch(self.config_sha256):
            raise ValueError("config_sha256 must be 64 lowercase hex characters")
        if not isinstance(self.scenario_plan_sha256, str) or not _SHA256_HEX.fullmatch(self.scenario_plan_sha256):
            raise ValueError("scenario_plan_sha256 must be 64 lowercase hex characters")


def build_manifest(
    config: GeneratorConfig, plan: ScenarioPlan | None = None, ranges: ScenarioRanges | None = None
) -> DatasetManifest:
    return DatasetManifest(
        seed=config.seed,
        schema_version=SCHEMA_VERSION,
        generator_version=GENERATOR_VERSION,
        config_sha256=canonical_config_hash(config),
        scenario_plan_sha256=scenario_plan_sha256(plan if plan is not None else ScenarioPlan(), ranges),
    )
