"""Reproducibility of the benign generator.

Determinism is checked in-process and across subprocesses with different
PYTHONHASHSEED values, which is where hash-order leaks would appear.
"""

import inspect
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import GeneratedDataset, generate

UTC = timezone.utc


def rows(dataset: GeneratedDataset) -> list[list[object]]:
    # Canonical view of a dataset: events and labels, in event order.
    # Uses attribute access only, so its source can be run in a subprocess.
    out: list[list[object]] = []
    for event in dataset.events:
        label = dataset.ground_truth.label_for(event.event_id)
        out.append(
            [
                event.event_id,
                event.timestamp_utc.isoformat(),
                event.account_id,
                event.source_ip,
                event.outcome.value,
                event.country_code,
                label.scenario_type.value,
                label.campaign_id,
                label.is_malicious,
            ]
        )
    return out


def reference_config(seed: int = 7, n_events: int = 300, n_accounts: int = 20) -> GeneratorConfig:
    return GeneratorConfig(
        seed=seed,
        start_utc=datetime(2026, 1, 1, 0, 0, tzinfo=UTC),
        duration_hours=24,
        n_accounts=n_accounts,
        n_events=n_events,
    )


def test_same_config_gives_identical_events_and_labels() -> None:
    config = reference_config()
    assert rows(generate(config)) == rows(generate(config))


def test_same_config_gives_equal_manifest() -> None:
    config = reference_config()
    assert generate(config).manifest == generate(config).manifest


def test_different_seeds_give_different_datasets() -> None:
    assert rows(generate(reference_config(seed=1, n_events=200))) != rows(
        generate(reference_config(seed=2, n_events=200))
    )


def test_output_does_not_depend_on_global_random_seed() -> None:
    config = reference_config()
    random.seed(1)
    first = rows(generate(config))
    random.seed(2)
    second = rows(generate(config))
    assert first == second


@pytest.mark.parametrize(
    "config",
    [
        reference_config(seed=7, n_events=300, n_accounts=20),
        reference_config(seed=2**63 - 1, n_events=50, n_accounts=100),
    ],
    ids=["regular", "fewer-events-than-accounts"],
)
@pytest.mark.parametrize("hash_seed", ["0", "1", "12345"])
def test_output_is_identical_across_pythonhashseed(config: GeneratorConfig, hash_seed: str) -> None:
    script = "\n".join(
        [
            "import json",
            "from datetime import datetime, timezone",
            "from login_anomaly.simulation.config import GeneratorConfig",
            # rows() carries a GeneratedDataset annotation, so the name must exist in the subprocess.
            "from login_anomaly.simulation.generator import GeneratedDataset, generate",
            inspect.getsource(rows),
            f"config = GeneratorConfig(seed={config.seed}, "
            f"start_utc=datetime({config.start_utc.year}, {config.start_utc.month}, "
            f"{config.start_utc.day}, tzinfo=timezone.utc), "
            f"duration_hours={config.duration_hours}, n_accounts={config.n_accounts}, "
            f"n_events={config.n_events})",
            "print(json.dumps(rows(generate(config))))",
        ]
    )
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    expected = json.dumps(rows(generate(config)))
    assert completed.stdout.strip() == expected
