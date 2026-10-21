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
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone

import pytest

from login_anomaly.simulation.config import GeneratorConfig
from login_anomaly.simulation.generator import GeneratedDataset, generate, generate_with_truth

UTC = timezone.utc
CHILD_TIMEOUT_SECONDS = 120


@pytest.fixture
def restore_global_random() -> Iterator[None]:
    state = random.getstate()
    yield
    random.setstate(state)


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


def reference_config(
    seed: int = 7,
    n_events: int = 300,
    n_accounts: int = 20,
    start: datetime = datetime(2026, 1, 1, 0, 0, tzinfo=UTC),
) -> GeneratorConfig:
    return GeneratorConfig(
        seed=seed,
        start_utc=start,
        duration_hours=24,
        n_accounts=n_accounts,
        n_events=n_events,
    )


def _run_child(script: str, hash_seed: str, *args: str) -> subprocess.CompletedProcess[str]:
    # Minimal environment: the child must not inherit parent variables.
    # The child runs in an empty temporary directory: `python -c` puts the current
    # directory on sys.path, so a stray module in the repository could shadow a stdlib import.
    # Note: -I is deliberately NOT used. It makes the interpreter ignore PYTHONHASHSEED,
    # which would turn the hash-seed determinism test into a vacuous check.
    env = {"PYTHONHASHSEED": hash_seed, "PATH": os.environ.get("PATH", "")}
    with tempfile.TemporaryDirectory() as empty_dir:
        return subprocess.run(
            [sys.executable, "-c", script, *args],
            env=env,
            cwd=empty_dir,
            capture_output=True,
            text=True,
            check=False,
            timeout=CHILD_TIMEOUT_SECONDS,
        )


CHILD_SCRIPT = "\n".join(
    [
        "import json, sys",
        "from datetime import datetime",
        "from login_anomaly.simulation.config import GeneratorConfig",
        # rows() carries a GeneratedDataset annotation, so the name must exist in the child.
        "from login_anomaly.simulation.generator import GeneratedDataset, generate_with_truth",
        inspect.getsource(rows),
        "p = json.loads(sys.argv[1])",
        "config = GeneratorConfig(",
        "    seed=p['seed'],",
        "    start_utc=datetime.fromisoformat(p['start_utc']),",
        "    duration_hours=p['duration_hours'],",
        "    n_accounts=p['n_accounts'],",
        "    n_events=p['n_events'],",
        ")",
        "print(json.dumps(rows(generate_with_truth(config))))",
    ]
)


def _config_as_json(config: GeneratorConfig) -> str:
    return json.dumps(
        {
            "seed": config.seed,
            "start_utc": config.start_utc.isoformat(),
            "duration_hours": config.duration_hours,
            "n_accounts": config.n_accounts,
            "n_events": config.n_events,
        }
    )


def test_same_config_gives_identical_events_and_labels() -> None:
    config = reference_config()
    assert rows(generate_with_truth(config)) == rows(generate_with_truth(config))


def test_same_config_gives_equal_manifest() -> None:
    config = reference_config()
    assert generate(config).manifest == generate(config).manifest


def test_different_seeds_give_different_datasets() -> None:
    assert rows(generate_with_truth(reference_config(seed=1, n_events=200))) != rows(
        generate_with_truth(reference_config(seed=2, n_events=200))
    )


def test_output_does_not_depend_on_global_random_seed(restore_global_random: None) -> None:
    config = reference_config()
    random.seed(1)
    first = rows(generate_with_truth(config))
    random.seed(2)
    second = rows(generate_with_truth(config))
    assert first == second


@pytest.mark.parametrize(
    "config",
    [
        reference_config(seed=7, n_events=300, n_accounts=20),
        reference_config(seed=2**63 - 1, n_events=50, n_accounts=100),
        reference_config(seed=5, n_events=400, n_accounts=30, start=datetime(2026, 3, 15, 10, 30, tzinfo=UTC)),
    ],
    ids=["regular", "fewer-events-than-accounts", "non-midnight-start"],
)
@pytest.mark.parametrize("hash_seed", ["0", "1", "12345"])
def test_output_is_identical_across_pythonhashseed(config: GeneratorConfig, hash_seed: str) -> None:
    completed = _run_child(CHILD_SCRIPT, hash_seed, _config_as_json(config))
    assert completed.returncode == 0, completed.stderr
    expected = json.dumps(rows(generate_with_truth(config)))
    assert completed.stdout.strip() == expected


def test_child_does_not_inherit_parent_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # The interpreter adds its own variables (for example LC_CTYPE on macOS), so the test
    # checks non-inheritance with a sentinel the parent sets, not with an exact key list.
    monkeypatch.setenv("LOGIN_ANOMALY_TEST_SENTINEL", "must-not-leak")
    script = "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('LOGIN_ANOMALY_TEST_SENTINEL', 'PYTHONHASHSEED')}))"
    completed = _run_child(script, "7")
    assert completed.returncode == 0, completed.stderr
    seen = json.loads(completed.stdout)
    assert seen["LOGIN_ANOMALY_TEST_SENTINEL"] is None
    assert seen["PYTHONHASHSEED"] == "7"


def test_child_subprocess_has_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _run_child("pass", "0")
    assert captured["timeout"] == CHILD_TIMEOUT_SECONDS == 120
