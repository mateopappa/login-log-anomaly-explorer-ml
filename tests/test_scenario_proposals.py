"""Scenario-agent proposals are constrained data, never executable instructions."""

import pytest

from login_anomaly.threat_lab.proposals import MockScenarioProvider, ScenarioProposalError, validate_proposal


def test_mock_proposal_becomes_a_reproducible_scenario_spec() -> None:
    first = validate_proposal(MockScenarioProvider().propose())
    second = validate_proposal(MockScenarioProvider().propose())
    assert first == second and first.fingerprint() == second.fingerprint()
    assert first.strategy == "agent_proposal"


@pytest.mark.parametrize(
    "raw",
    [
        {"code": "import os"},
        {"scenario_id": "x", "description": "x", "seeds": (1,), "plan": {}, "ranges": {}, "tags": (), "extra": "x"},
        {"scenario_id": "bad id", "description": "x", "seeds": (1,), "plan": {}, "ranges": {}, "tags": ()},
        {"scenario_id": "valid", "description": "x", "seeds": (1,), "plan": {"unknown": 1}, "ranges": {}, "tags": ()},
    ],
)
def test_invalid_or_executable_proposals_fail_safely(raw) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ScenarioProposalError):
        validate_proposal(raw)
