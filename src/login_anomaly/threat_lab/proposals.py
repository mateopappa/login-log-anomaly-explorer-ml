"""Validated, non-executable scenario proposals for future scenario agents."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from login_anomaly.simulation.scenarios import ScenarioPlan, ScenarioRanges
from login_anomaly.threat_lab.specs import ScenarioSpec

_FIELDS = frozenset({"scenario_id", "description", "seeds", "plan", "ranges", "tags"})


class ScenarioProposalError(ValueError):
    """Raised when an untrusted scenario proposal is outside the fixed schema."""


class ScenarioProposalProvider(Protocol):
    @property
    def mode(self) -> str: ...

    @property
    def provider_id(self) -> str: ...

    def propose(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class MockScenarioProvider:
    """A deterministic local proposal source for tests and manual Threat Lab demos."""

    mode: str = "mock"
    provider_id: str = "deterministic-scenario-mock-v1"

    def propose(self) -> Mapping[str, Any]:
        return {
            "scenario_id": "mock_benign_shift",
            "description": "Mock proposal with benign roaming and shared-address decoys.",
            "seeds": (1201, 1202),
            "plan": {"bruteforce_campaigns": 1, "benign_travelers": 12, "benign_decoys": 6},
            "ranges": {},
            "tags": ("mock", "distribution_shift"),
        }


def validate_proposal(raw: Mapping[str, Any], *, strategy: str = "agent_proposal") -> ScenarioSpec:
    """Convert untrusted structured data to a generator-safe ``ScenarioSpec``.

    There is deliberately no code, callable, path, or free-form configuration
    field in the proposal schema.  ``ScenarioPlan``, ``ScenarioRanges``, and
    ``ScenarioSpec`` supply the deterministic range and reproducibility checks.
    """
    if not isinstance(raw, Mapping) or set(raw) != _FIELDS:
        raise ScenarioProposalError(f"proposal fields must be exactly {sorted(_FIELDS)}")
    try:
        return ScenarioSpec(
            scenario_id=raw["scenario_id"],
            strategy=strategy,
            description=raw["description"],
            seeds=tuple(raw["seeds"]),
            plan=ScenarioPlan(**raw["plan"]),
            ranges=ScenarioRanges(**raw["ranges"]),
            tags=tuple(raw["tags"]),
        )
    except (TypeError, ValueError) as error:
        raise ScenarioProposalError(f"invalid scenario proposal: {error}") from None
