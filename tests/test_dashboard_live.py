"""SOC Live tab rendered headlessly: controls, state labels, and separation between sessions."""

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = Path(__file__).resolve().parents[1] / "src" / "login_anomaly" / "dashboard" / "app.py"


def markdown_text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def test_soc_live_renders_idle_with_mock_indicator() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert "SOC Live" in [h.value for h in at.subheader]
    assert any("No simulation is running" in i.value for i in at.info)
    assert any("Mock agents" in i.value for i in at.info)
    assert at.button(key="live_start").disabled is False
    assert at.button(key="live_pause").disabled is True and at.button(key="live_reset").disabled is True


def test_start_pause_resume_reset_drive_the_state_and_buttons() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    at.button(key="live_start").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert "Status: RUNNING" in markdown_text(at)
    assert at.button(key="live_start").disabled is True  # no second simulation while one exists
    assert at.button(key="live_pause").disabled is False

    at.button(key="live_pause").click().run()
    assert "Status: PAUSED" in markdown_text(at)
    assert at.button(key="live_resume").disabled is False

    at.button(key="live_resume").click().run()
    assert "Status: RUNNING" in markdown_text(at)

    at.button(key="live_reset").click().run()
    assert any("No simulation is running" in i.value for i in at.info)
    assert at.button(key="live_start").disabled is False


def test_two_browser_sessions_do_not_share_a_simulation() -> None:
    first = AppTest.from_file(str(APP), default_timeout=120).run()
    second = AppTest.from_file(str(APP), default_timeout=120).run()
    first.button(key="live_start").click().run()
    second.run()
    assert "Status: RUNNING" in markdown_text(first)
    assert any("No simulation is running" in i.value for i in second.info)


def test_mock_and_real_modes_are_labelled_in_the_existing_tabs() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("mode: mock" in c.value for c in at.caption)


def test_stop_ends_the_run_and_says_so() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    at.button(key="live_start").click().run()
    at.button(key="live_stop").click().run()
    assert "Status: COMPLETED" in markdown_text(at)
    assert "Stopped by user" in markdown_text(at)
    assert at.button(key="live_stop").disabled is True


def caption_text(at: AppTest) -> str:
    return "\n".join(c.value for c in at.caption)


def test_detector_flags_control_live_processing_configurations() -> None:
    # 1. Ingestion baseline: neither detector enabled
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    at.checkbox(key="live_enable_rules").uncheck().run()
    at.checkbox(key="live_enable_ml").uncheck().run()
    assert "Neither detector (Ingestion baseline" in caption_text(at)
    at.button(key="live_start").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert "Status: RUNNING" in markdown_text(at)
    assert "Rules: `DISABLED` · ML: `DISABLED`" in caption_text(at)
    rule_alert_values = [m.value for m in at.metric if m.label == "Rule alerts"]
    assert "0" in rule_alert_values

    # 2. Rules only
    at2 = AppTest.from_file(str(APP), default_timeout=120).run()
    at2.checkbox(key="live_enable_ml").uncheck().run()
    assert "Rules only" in caption_text(at2)
    at2.button(key="live_start").click().run()
    assert not at2.exception, [e.value for e in at2.exception]
    assert "Rules: `ACTIVE` · ML: `DISABLED`" in caption_text(at2)

    # 3. ML only
    at3 = AppTest.from_file(str(APP), default_timeout=120).run()
    at3.checkbox(key="live_enable_rules").uncheck().run()
    assert "ML only" in caption_text(at3)
    at3.button(key="live_start").click().run()
    assert not at3.exception, [e.value for e in at3.exception]
    assert "Rules: `DISABLED` · ML: `ACTIVE`" in caption_text(at3)


def test_live_benchmark_runs_4_way_comparison() -> None:
    at = AppTest.from_file(str(APP), default_timeout=120).run()
    at.button(key="live_run_benchmark").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Side-by-Side Results for Scenario" in m.value for m in at.markdown)
    # Check that the comparison dataframe is rendered
    df_values = [df.value.to_string() for df in at.dataframe]
    assert any("Rules + ML" in s and "Neither detector" in s for s in df_values)
