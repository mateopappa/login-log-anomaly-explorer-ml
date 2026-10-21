import dataclasses
import hashlib
import json
from datetime import datetime, timezone

import pytest

from login_anomaly.events import SCHEMA_VERSION
from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.manifest import (
    GENERATOR_VERSION,
    DatasetManifest,
    build_manifest,
    canonical_config_hash,
    canonical_config_json,
)

UTC = timezone.utc

# Canonical JSON of the reference config below, written out by hand. Keys sorted,
# no spaces, timestamp in ISO 8601 with an explicit +00:00 offset.
REFERENCE_CANONICAL_JSON = (
    '{"duration_hours":24,"n_accounts":10,"n_events":500,'
    '"seed":42,"start_utc":"2026-01-01T00:00:00+00:00"}'
)


def reference_config() -> GeneratorConfig:
    return GeneratorConfig(
        seed=42,
        start_utc=datetime(2026, 1, 1, 0, 0, tzinfo=UTC),
        duration_hours=24,
        n_accounts=10,
        n_events=500,
    )


def test_canonical_json_matches_hand_written_literal() -> None:
    assert canonical_config_json(reference_config()) == REFERENCE_CANONICAL_JSON


def test_canonical_json_keys_are_sorted() -> None:
    keys = list(json.loads(canonical_config_json(reference_config())))
    assert keys == sorted(keys)


def test_hash_matches_sha256_of_literal_canonical_json() -> None:
    expected = hashlib.sha256(REFERENCE_CANONICAL_JSON.encode("utf-8")).hexdigest()
    assert canonical_config_hash(reference_config()) == expected


def test_hash_is_64_lowercase_hex() -> None:
    digest = canonical_config_hash(reference_config())
    assert len(digest) == 64
    assert digest == digest.lower()
    int(digest, 16)


def test_hash_is_stable_across_equal_configs() -> None:
    assert canonical_config_hash(reference_config()) == canonical_config_hash(reference_config())


@pytest.mark.parametrize(
    "changed",
    [
        {"seed": 43},
        {"start_utc": datetime(2026, 1, 2, 0, 0, tzinfo=UTC)},
        {"duration_hours": 25},
        {"n_accounts": 11},
        {"n_events": 501},
    ],
)
def test_hash_changes_when_any_field_changes(changed: dict[str, object]) -> None:
    base = reference_config()
    other = dataclasses.replace(base, **changed)  # type: ignore[arg-type]
    assert canonical_config_hash(other) != canonical_config_hash(base)


def test_manifest_field_names_are_exact() -> None:
    names = {f.name for f in dataclasses.fields(DatasetManifest)}
    assert names == {"seed", "schema_version", "generator_version", "config_sha256"}


def test_manifest_is_frozen() -> None:
    manifest = build_manifest(reference_config())
    with pytest.raises(dataclasses.FrozenInstanceError):
        manifest.seed = 1  # type: ignore[misc]


def test_build_manifest_records_provenance() -> None:
    config = reference_config()
    manifest = build_manifest(config)
    assert manifest.seed == 42
    assert manifest.schema_version == "1.0.0"
    assert manifest.schema_version == SCHEMA_VERSION
    assert manifest.generator_version == GENERATOR_VERSION
    assert manifest.config_sha256 == canonical_config_hash(config)


def test_generator_version_is_set() -> None:
    assert GENERATOR_VERSION == "0.1.0"


@pytest.mark.parametrize("digest", ["abc", "A" * 64, "g" * 64, "a" * 63])
def test_manifest_rejects_malformed_config_sha256(digest: str) -> None:
    with pytest.raises(ValueError):
        DatasetManifest(
            seed=42,
            schema_version="1.0.0",
            generator_version="0.1.0",
            config_sha256=digest,
        )


def test_manifest_rejects_empty_generator_version() -> None:
    with pytest.raises(ValueError):
        DatasetManifest(
            seed=42,
            schema_version="1.0.0",
            generator_version="",
            config_sha256="a" * 64,
        )
