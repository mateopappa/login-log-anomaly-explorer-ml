import dataclasses

import pytest

from login_anomaly.simulation.ground_truth import GroundTruth, ScenarioLabel, ScenarioType


def benign(event_id: str = "evt-000001") -> ScenarioLabel:
    return ScenarioLabel(
        event_id=event_id,
        scenario_type=ScenarioType.BENIGN,
        campaign_id=None,
        is_malicious=False,
    )


def attack(event_id: str = "evt-000002") -> ScenarioLabel:
    return ScenarioLabel(
        event_id=event_id,
        scenario_type=ScenarioType.BRUTEFORCE,
        campaign_id="camp-001",
        is_malicious=True,
    )


def test_scenario_type_values() -> None:
    assert {s.value for s in ScenarioType} == {
        "benign",
        "bruteforce",
        "password_spraying",
        "impossible_travel",
    }


def test_label_field_names_are_exact() -> None:
    names = {f.name for f in dataclasses.fields(ScenarioLabel)}
    assert names == {"event_id", "scenario_type", "campaign_id", "is_malicious"}


def test_label_is_frozen() -> None:
    label = benign()
    with pytest.raises(dataclasses.FrozenInstanceError):
        label.is_malicious = True  # type: ignore[misc]


def test_benign_label_is_accepted_without_campaign() -> None:
    label = benign()
    assert label.campaign_id is None
    assert label.is_malicious is False


def test_attack_label_is_accepted_with_campaign() -> None:
    label = attack()
    assert label.campaign_id == "camp-001"
    assert label.is_malicious is True


@pytest.mark.parametrize(
    "scenario_type",
    [ScenarioType.BRUTEFORCE, ScenarioType.PASSWORD_SPRAYING, ScenarioType.IMPOSSIBLE_TRAVEL],
)
def test_attack_label_without_campaign_is_rejected(scenario_type: ScenarioType) -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", scenario_type, None, True)


def test_benign_label_with_campaign_is_rejected() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, "camp-001", False)


def test_attack_label_marked_not_malicious_is_rejected() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", ScenarioType.BRUTEFORCE, "camp-001", False)


def test_benign_label_marked_malicious_is_rejected() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, None, True)


def test_label_rejects_empty_event_id() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("", ScenarioType.BENIGN, None, False)


def test_label_rejects_string_instead_of_scenario_type() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", "benign", None, False)  # type: ignore[arg-type]


def test_label_rejects_non_bool_is_malicious() -> None:
    with pytest.raises(ValueError):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, None, 0)  # type: ignore[arg-type]


def test_ground_truth_returns_label_for_event_id() -> None:
    truth = GroundTruth([benign("evt-1"), attack("evt-2")])
    assert truth.label_for("evt-2") == attack("evt-2")


def test_ground_truth_unknown_event_id_raises_key_error() -> None:
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(KeyError):
        truth.label_for("evt-404")


def test_ground_truth_rejects_duplicate_event_id() -> None:
    with pytest.raises(ValueError):
        GroundTruth([benign("evt-1"), attack("evt-1")])


def test_ground_truth_rejects_non_label_entries() -> None:
    with pytest.raises(ValueError):
        GroundTruth(["evt-1"])  # type: ignore[list-item]


def test_ground_truth_len_and_contains() -> None:
    truth = GroundTruth([benign("evt-1"), attack("evt-2")])
    assert len(truth) == 2
    assert "evt-1" in truth
    assert "evt-404" not in truth


def test_ground_truth_contains_unhashable_is_false_not_error() -> None:
    truth = GroundTruth([benign("evt-1")])
    assert ["evt-1"] not in truth


def test_empty_ground_truth_is_allowed() -> None:
    truth = GroundTruth([])
    assert len(truth) == 0
    assert "evt-1" not in truth


def test_ground_truth_is_read_only() -> None:
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(TypeError):
        truth["evt-1"] = attack("evt-1")  # type: ignore[index]
