"""Renders the Streamlit app headlessly with AppTest. Skipped when the dashboard extra is not installed."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "src" / "login_anomaly" / "dashboard" / "app.py"


def test_app_renders_without_exceptions() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value == "Login-log anomaly explorer"


def test_investigations_tab_shows_real_investigations_and_labelled_fixtures() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    metrics = {m.label: m.value for m in at.metric}
    assert int(metrics["Rule alerts"]) > 0
    assert metrics["Investigated"] == metrics["Rule alerts"]
    assert "Scored" in metrics  # evaluation shown by default, marked as using labels
    subheaders = [h.value for h in at.subheader]
    assert "Case workbench · label-free runtime" in subheaders  # rule and ML cases share one workflow
    captions = [c.value for c in at.caption]
    assert any("mode: mock" in text for text in captions)  # execution mode is explicit
    assert any(text.startswith("Simulated") for text in captions)  # fixtures kept, labelled as simulated
    assert any(text.startswith("Simulated") for text in captions)  # fixtures kept, labelled as simulated


def test_selecting_an_alert_shows_its_investigation() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    box = at.selectbox(key="agentic_alert")
    last = box.options[-1]
    box.select(last).run()
    assert not at.exception, [e.value for e in at.exception]
    assert any(last in m.value for m in at.markdown)
    assert any(m.label == "Tool calls" for m in at.metric)


def test_evaluation_can_be_hidden() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    at.toggle(key="agentic_show_eval").set_value(False).run()
    assert not at.exception, [e.value for e in at.exception]
    labels = {m.label for m in at.metric}
    assert "Scored" not in labels and "Investigated" in labels


def test_dataset_without_campaigns_renders() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    for index in (4, 5, 6, 7):  # bruteforce, spraying, travel, travelers
        at.sidebar.number_input[index].set_value(0)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    metrics = {m.label: m.value for m in at.metric}
    if int(metrics["Rule alerts"]) == 0:
        assert any("No rule alerts to investigate" in i.value for i in at.info)


def test_plan_that_does_not_fit_the_budget_shows_an_error_not_a_crash() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120)
    at.run()
    # Sidebar number inputs in order: seed, n_events, n_accounts, duration, bruteforce, ...
    at.sidebar.number_input[1].set_value(20).run()  # n_events: far too small for the plan
    at.sidebar.number_input[4].set_value(50).run()  # bruteforce campaigns
    assert not at.exception, [e.value for e in at.exception]
    assert any("Generation rejected" in e.value for e in at.error)


def test_threat_lab_tab_shows_the_catalog_and_rules_versus_ml() -> None:
    at = AppTest.from_file(str(APP), default_timeout=300).run()
    assert not at.exception, [e.value for e in at.exception]
    headers = [h.value for h in at.subheader]
    assert "Scenario catalog" in headers and "Rules versus ML, per scenario" in headers
    assert "Mock scenario proposal" in headers
    assert any("use ground-truth labels for scoring" in w.value for w in at.warning)
    assert any(f.label == "Scenario" for f in at.selectbox)
    assert any("nominal_control" in df.value.to_string() for df in at.dataframe)
