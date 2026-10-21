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
from login_anomaly.simulation.config import GeneratorConfig

GENERATOR_VERSION = "0.1.0"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


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

    def __post_init__(self) -> None:
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an int")
        if not isinstance(self.schema_version, str) or not self.schema_version:
            raise ValueError("schema_version must be a non-empty string")
        if not isinstance(self.generator_version, str) or not self.generator_version:
            raise ValueError("generator_version must be a non-empty string")
        if not isinstance(self.config_sha256, str) or not _SHA256_HEX.fullmatch(self.config_sha256):
            raise ValueError("config_sha256 must be 64 lowercase hex characters")


def build_manifest(config: GeneratorConfig) -> DatasetManifest:
    return DatasetManifest(
        seed=config.seed,
        schema_version=SCHEMA_VERSION,
        generator_version=GENERATOR_VERSION,
        config_sha256=canonical_config_hash(config),
    )
