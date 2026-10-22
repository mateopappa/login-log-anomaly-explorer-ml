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
    with pytest.raises(ValueError, match="campaign_id"):
        ScenarioLabel("evt-1", scenario_type, None, True)


@pytest.mark.parametrize("campaign_id", ["", 7])
def test_attack_label_rejects_empty_or_non_string_campaign_id(campaign_id: object) -> None:
    with pytest.raises(ValueError, match="campaign_id"):
        ScenarioLabel("evt-1", ScenarioType.BRUTEFORCE, campaign_id, True)  # type: ignore[arg-type]


def test_benign_label_with_campaign_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not have a campaign_id"):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, "camp-001", False)


def test_attack_label_marked_not_malicious_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be malicious"):
        ScenarioLabel("evt-1", ScenarioType.BRUTEFORCE, "camp-001", False)


def test_benign_label_marked_malicious_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be malicious"):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, None, True)


def test_label_rejects_empty_event_id() -> None:
    with pytest.raises(ValueError, match="event_id"):
        ScenarioLabel("", ScenarioType.BENIGN, None, False)


def test_label_rejects_string_instead_of_scenario_type() -> None:
    with pytest.raises(ValueError, match="ScenarioType"):
        ScenarioLabel("evt-1", "benign", None, False)  # type: ignore[arg-type]


def test_label_rejects_non_bool_is_malicious() -> None:
    with pytest.raises(ValueError, match="must be a bool"):
        ScenarioLabel("evt-1", ScenarioType.BENIGN, None, 0)  # type: ignore[arg-type]


def test_ground_truth_returns_label_for_event_id() -> None:
    truth = GroundTruth([benign("evt-1"), attack("evt-2")])
    assert truth.label_for("evt-2") == attack("evt-2")


def test_ground_truth_unknown_event_id_raises_key_error_naming_the_id() -> None:
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(KeyError, match="evt-404"):
        truth.label_for("evt-404")


@pytest.mark.parametrize("key", [[], {}, None, 5])
def test_ground_truth_non_string_key_raises_value_error(key: object) -> None:
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(ValueError, match="event_id must be a string"):
        truth.label_for(key)  # type: ignore[arg-type]


def test_ground_truth_rejects_duplicate_event_id() -> None:
    with pytest.raises(ValueError, match="duplicate event_id"):
        GroundTruth([benign("evt-1"), attack("evt-1")])


def test_ground_truth_rejects_non_label_entries() -> None:
    with pytest.raises(ValueError, match="only ScenarioLabel"):
        GroundTruth(["evt-1"])  # type: ignore[list-item]


@pytest.mark.parametrize("labels", [5, None])
def test_ground_truth_rejects_non_iterable_with_value_error(labels: object) -> None:
    with pytest.raises(ValueError, match="iterable"):
        GroundTruth(labels)  # type: ignore[arg-type]


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


def test_ground_truth_is_read_only_through_item_assignment() -> None:
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(TypeError):
        truth["evt-1"] = attack("evt-1")  # type: ignore[index]


def test_ground_truth_index_cannot_be_mutated_through_internal_attribute() -> None:
    # The index is exposed only as a read-only mapping view, even to code that reaches for the private name.
    truth = GroundTruth([benign("evt-1")])
    with pytest.raises(TypeError):
        truth._by_event_id["evt-1"] = attack("evt-1")  # type: ignore[index]


def test_ground_truth_exposes_no_public_mutators() -> None:
    public = {name for name in dir(GroundTruth) if not name.startswith("_")}
    assert public == {"label_for"}
