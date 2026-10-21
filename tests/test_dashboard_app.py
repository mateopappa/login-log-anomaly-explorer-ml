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


def test_app_shows_the_agentic_panel_as_simulated() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    warnings = [w.value for w in at.warning]
    assert any("Simulated" in text for text in warnings)


def test_plan_that_does_not_fit_the_budget_shows_an_error_not_a_crash() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120)
    at.run()
    # Sidebar number inputs in order: seed, n_events, n_accounts, duration, bruteforce, ...
    at.sidebar.number_input[1].set_value(20).run()  # n_events: far too small for the plan
    at.sidebar.number_input[4].set_value(50).run()  # bruteforce campaigns
    assert not at.exception, [e.value for e in at.exception]
    assert any("Generation rejected" in e.value for e in at.error)
