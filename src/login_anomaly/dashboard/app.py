"""Local Streamlit app. Run: streamlit run src/login_anomaly/dashboard/app.py

It renders what ``dashboard.view``, ``evaluation.panel`` and ``evaluation.investigation``
compute. It contains no detection or investigation logic. Synthetic data only.
"""

from __future__ import annotations

import streamlit as st

from login_anomaly.dashboard.view import (
    COMPONENT_STATUS,
    SessionConfig,
    alert_rows,
    case_detail,
    case_rows,
    catalog_rows,
    events_for,
    explain_alert,
    investigation_detail,
    investigation_rows,
    investigation_summary,
    live_case_detail,
    live_case_rows,
    related_events,
    scenario_detail,
    workflow_for,
)
from login_anomaly.evaluation.experiment import train_baseline
from login_anomaly.evaluation.investigation import evaluate_investigations
from login_anomaly.evaluation.live import compare_replay_detector_configurations, evaluate_live_replay
from login_anomaly.evaluation.panel import comparison_rows, truth_for
from login_anomaly.evaluation.threat_lab import comparison_rows as lab_comparison_rows
from login_anomaly.evaluation.threat_lab import run_lab, run_proposal
from login_anomaly.live.engine import DEFAULT_RATE, MAX_RATE, MIN_RATE, LiveConfig, SimulationService
from login_anomaly.live.sources import ATTACK_FAMILIES, REPLAY_SCENARIOS
from login_anomaly.simulation.scenarios import ScenarioPlan
from login_anomaly.threat_lab.proposals import MockScenarioProvider, ScenarioProposalError
from login_anomaly.threat_lab.specs import build_catalog

# Hand-written cases that check the evaluator in the test suite. They are not investigations.
AGENTIC_FIXTURES = [
    ("Correct investigation", "verdict correct, evidence cited"),
    ("False positive", "malicious verdict on a benign alert"),
    ("False negative", "benign verdict on a true alert"),
    ("Insufficient evidence", "malicious verdict with no evidence"),
    ("Irrelevant evidence", "evidence on a non-observable field"),
    ("Malformed result", "rejected by the parser"),
    ("Forbidden tool", "tool outside the read-only set"),
    ("Ground-truth access attempt", "argument asks for labels"),
    ("Excess calls", "more tool calls than allowed"),
]
VERDICT_COLORS = {"malicious": "red", "benign": "green", "inconclusive": "orange"}


# Every widget interaction reruns the script. These caches keep the generator, the model,
# the detector and the investigator from running again for the same session settings.
@st.cache_resource(show_spinner="Training the ML baseline on the training seeds...")
def baseline_model() -> tuple[object, int, int]:
    return train_baseline()


@st.cache_resource(show_spinner="Generating events...")
def events_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return events_for(session)


@st.cache_resource(show_spinner="Running the label-free case workflow...")
def workflow_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return workflow_for(baseline_model()[0], events_cached(session))


@st.cache_resource(show_spinner="Investigating rule alerts...")
def investigations_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    # Observable events and rule alerts only. No labels reach the investigator.
    return workflow_cached(session).investigations


@st.cache_resource(show_spinner="Running the Threat Lab scenarios (rules and ML on the same events)...")
def lab_cached():  # type: ignore[no-untyped-def]
    # Reuses the baseline already trained for the session; the lab never retrains or changes it.
    return run_lab(build_catalog(), baseline_model()[0])


@st.cache_resource(show_spinner="Validating and running the mock scenario proposal...")
def proposal_cached():  # type: ignore[no-untyped-def]
    return run_proposal(MockScenarioProvider(), baseline_model()[0])


@st.cache_resource(show_spinner="Generating events and labels for the evaluation panel...")
def truth_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return truth_for(session.seed, session.n_events, session.n_accounts, session.duration_hours, session.plan)


@st.cache_resource(show_spinner="Scoring investigations against labels...")
def evaluations_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return evaluate_investigations(investigations_cached(session), truth_cached(session).ground_truth)


def verdict_badge(verdict: str | None) -> str:
    return f":{VERDICT_COLORS.get(verdict or '', 'gray')}[**{verdict or 'n/a'}**]"


# SOC Live. Each browser session keeps its own service in st.session_state, so sessions never share state.
LIVE_KEY = "soc_live_service"
LIVE_MODES = {"Replay": "replay", "Continuous": "continuous"}


def live_start() -> None:
    state = st.session_state
    try:
        config = LiveConfig(
            mode=LIVE_MODES[state["live_mode"]],
            seed=int(state["live_seed"]),
            scenario=state["live_scenario"],
            attacks=frozenset(state["live_attacks"]),
            events_per_second=float(state["live_rate"]),
            enable_rules=bool(state.get("live_enable_rules", True)),
            enable_ml=bool(state.get("live_enable_ml", True)),
        )
    except ValueError as error:
        state["live_error"] = f"Configuration rejected: {error}"
        return
    state["live_error"] = None
    service = SimulationService(config, baseline_model()[0])
    service.start()
    state[LIVE_KEY] = service


def live_action(name: str) -> None:
    if name == "reset":
        st.session_state[LIVE_KEY] = None  # a fresh IDLE session on the next Start
        st.session_state.pop("live_current_eval", None)
    elif st.session_state.get(LIVE_KEY) is not None:
        getattr(st.session_state[LIVE_KEY], name)()


def _render_case_dossier(detail: dict[str, Any]) -> None:
    """Evidence-first progressive disclosure case dossier without raw json default."""
    st.markdown(f"#### Case Dossier: `{detail['case_id']}`")

    meta_cols = st.columns(4)
    meta_cols[0].metric("Origin", "Rule-backed" if detail["kind"] == "rule_backed" else "ML-only")
    meta_cols[1].metric("Priority", detail["priority"].replace("_", " ").upper())
    meta_cols[2].metric("Signals", detail["signals"])
    meta_cols[3].metric("Context Window", "In 2h window" if detail.get("in_window") else "Expired")

    st.markdown("**1. Contributing Detector Signals & Correlation Provenance**")
    if detail.get("signals_detail"):
        st.dataframe(detail["signals_detail"], use_container_width=True, hide_index=True)
    if detail.get("associations"):
        for a in detail["associations"]:
            st.caption(
                f"• Association basis: `{a['basis']}` · ML Signal `{a['ml_signal_id']}` correlated with "
                f"Rule Signal `{a['rule_signal_id'] or 'none'}` on Event `{a['event_id']}`"
            )

    st.markdown("**2. Observable Authentication Events (Supporting Evidence)**")
    if detail.get("events"):
        st.dataframe(detail["events"], use_container_width=True, hide_index=True)

    st.markdown("**3. Investigation Findings (Deterministic Mock Agent)**")
    if "verdict" in detail:
        v_col1, v_col2 = st.columns([1, 3])
        v_col1.metric("Verdict", detail["verdict"].upper(), delta=f"Confidence {detail['confidence']:.2f}")
        v_col2.info(f"**Reasoning:** {detail['justification']}")

        if detail.get("evidence"):
            st.markdown("**Verified Supporting Observations:**")
            for e in detail["evidence"]:
                st.write(f"- `{e.get('field', 'fact')}`: {e.get('observation', '')}")

        if detail.get("tool_calls"):
            with st.expander("Investigation Tool Execution Trace", expanded=False):
                tool_rows = [
                    {
                        "Step": idx,
                        "Tool": call.get("tool_name"),
                        "Status": call.get("status"),
                        "Arguments": str(call.get("arguments")),
                    }
                    for idx, call in enumerate(detail["tool_calls"], 1)
                ]
                st.dataframe(tool_rows, use_container_width=True, hide_index=True)
    else:
        st.warning(detail.get("note", "Case has not been investigated."))

    if "review" in detail and detail["review"]:
        st.markdown("**4. Runtime Reviewer Audit (Deterministic Mock Reviewer)**")
        r_cols = st.columns(2)
        r_cols[0].write(f"**Audit Quality:** `{detail['review'].get('quality', 'unknown')}`")
        if detail.get("uncertainty"):
            r_cols[1].warning(f"**Uncertainties:** {', '.join(detail['uncertainty'])}")
        else:
            r_cols[1].success("No policy violations or excessive uncertainty flagged.")

    with st.expander("Raw Case JSON Payload", expanded=False):
        st.json(detail, expanded=False)


def _render_completed_evaluation_section(service: SimulationService, state: str) -> None:
    st.markdown("### Ground-Truth Evaluation of Replay Run")
    st.caption(
        "Ground-truth evaluation is strictly isolated from runtime and compares output against "
        "held-out scenario labels. Evaluated only when requested."
    )

    if service.config.mode != "replay":
        st.info("Ground-truth run evaluation is available for Replay simulations with fixed nominal scenarios.")
        return

    eval_col1, eval_col2 = st.columns([1, 3])
    can_eval = state in ("completed", "paused", "running")
    if eval_col1.button("Score Run Against Ground Truth", disabled=not can_eval, key="live_eval_current"):
        try:
            st.session_state["live_current_eval"] = evaluate_live_replay(service)
        except Exception as err:
            st.error(f"Evaluation failed: {err}")

    eval_result = st.session_state.get("live_current_eval")
    if eval_result is not None:
        st.success(f"Evaluated replay run `{eval_result.scenario}` (Seed {eval_result.seed})")
        ecols = st.columns(4)
        ecols[0].metric("Released Events", eval_result.operational_counts.get("released", 0))
        ecols[1].metric("Processed Events", eval_result.operational_counts.get("processed", 0))
        ecols[2].metric("True Malicious Events", eval_result.malicious_events)
        ecols[3].metric("Total Cases Triaged", eval_result.operational_counts.get("cases_total", 0))

        r_col, m_col = st.columns(2)
        with r_col:
            st.markdown("**Rule Detector Quality**")
            rm = eval_result.rules_metrics
            if rm.enabled:
                rm_cols = st.columns(3)
                rm_cols[0].metric("Precision", f"{rm.precision:.3f}")
                rm_cols[1].metric("Recall", f"{rm.recall:.3f}")
                rm_cols[2].metric("F1 Score", f"{rm.f1:.3f}")
                st.caption(f"TP: {rm.tp} · FP: {rm.fp} · FN: {rm.fn}")
            else:
                st.caption("Rule detector was disabled for this run (no rule alerts evaluated).")

        with m_col:
            st.markdown("**ML Baseline Detector Quality**")
            mm = eval_result.ml_metrics
            if mm.enabled:
                mm_cols = st.columns(3)
                mm_cols[0].metric("Precision", f"{mm.precision:.3f}")
                mm_cols[1].metric("Recall", f"{mm.recall:.3f}")
                mm_cols[2].metric("F1 Score", f"{mm.f1:.3f}")
                st.caption(f"TP: {mm.tp} · FP: {mm.fp} · FN: {mm.fn}")
            else:
                st.caption("ML detector was disabled for this run (no ML anomaly signals evaluated).")


def _render_live_benchmark_panel() -> None:
    st.markdown("### Controlled 4-Way Detector Experiment")
    st.caption(
        "Runs the exact same replay scenario and seed under all 4 detector configurations "
        "(Rules + ML, Rules only, ML only, Ingestion baseline) to demonstrate real configuration impact."
    )

    b_cols = st.columns([2, 1, 1])
    bench_scenario = b_cols[0].selectbox("Benchmark scenario", list(REPLAY_SCENARIOS), key="live_bench_scenario")
    bench_seed = b_cols[1].number_input("Benchmark seed", min_value=0, max_value=2**53 - 1, value=31, step=1, key="live_bench_seed")
    run_bench = b_cols[2].button("Run 4-Way Benchmark", type="secondary", key="live_run_benchmark")

    if run_bench:
        with st.spinner("Executing 4 controlled replay simulations on identical event streams..."):
            try:
                results = compare_replay_detector_configurations(
                    scenario=bench_scenario,
                    seed=int(bench_seed),
                    model=baseline_model()[0],
                )
                st.session_state["live_benchmark_results"] = results
            except Exception as err:
                st.error(f"Benchmark error: {err}")

    bench_data = st.session_state.get("live_benchmark_results")
    if bench_data and isinstance(bench_data, list) and len(bench_data) > 0:
        first = bench_data[0]
        st.markdown(f"**Side-by-Side Results for Scenario `{first.scenario}` (Seed {first.seed}):**")
        bench_rows = []
        for res in bench_data:
            r_f1 = f"{res.rules_metrics.f1:.3f}" if res.rules_metrics.enabled else "—"
            m_f1 = f"{res.ml_metrics.f1:.3f}" if res.ml_metrics.enabled else "—"
            name = {
                "rules_and_ml": "Rules + ML",
                "rules_only": "Rules only",
                "ml_only": "ML only",
                "none": "Neither detector (Baseline)",
            }.get(res.detector_mode, res.detector_mode)
            ops = res.operational_counts
            bench_rows.append(
                {
                    "Configuration": name,
                    "Rules": "ON" if res.enable_rules else "OFF",
                    "ML": "ON" if res.enable_ml else "OFF",
                    "Processed": ops.get("processed", 0),
                    "Rule Alerts": ops.get("rule_alerts", 0),
                    "ML Positives": ops.get("ml_positive_events", 0),
                    "Total Cases": ops.get("cases_total", 0),
                    "Rule-backed": ops.get("cases_rule_backed", 0),
                    "ML-only": ops.get("cases_ml_only", 0),
                    "Rule F1": r_f1,
                    "ML F1": m_f1,
                }
            )
        st.dataframe(bench_rows, use_container_width=True, hide_index=True)
        st.caption(
            "Controlled comparison takeaways: In 'Neither detector', 0 alerts and 0 cases are generated (pure ingestion baseline). "
            "In 'Rules only', ML-only anomaly signals do not produce cases. "
            "In 'ML only', rule signatures do not fire and cases originate solely from event-level anomaly flags."
        )


@st.fragment(run_every=1.0)
def live_panel() -> None:
    # Re-runs every second on its own, so the page updates without a full reload.
    service: SimulationService | None = st.session_state.get(LIVE_KEY)
    if service is not None:
        service.advance()  # releases only the events the elapsed time has earned
    summary = service.summary() if service is not None else None
    state = summary["state"] if summary else "idle"
    busy = service is not None

    st.subheader("SOC Live")
    st.info(
        "**Mock agents.** The investigator and reviewer are deterministic and local. "
        "No LLM is called, no API key is used, and nothing is paid. Ground truth is not visible to any agent."
    )
    controls = st.columns(5)
    controls[0].radio("Mode", list(LIVE_MODES), horizontal=True, key="live_mode", disabled=busy)
    controls[1].selectbox("Replay scenario", list(REPLAY_SCENARIOS), key="live_scenario", disabled=busy, help="Used in replay mode.")
    controls[2].number_input("Seed", min_value=0, max_value=2**53 - 1, value=31, step=1, key="live_seed", disabled=busy)
    controls[3].multiselect("Attack families", list(ATTACK_FAMILIES), default=list(ATTACK_FAMILIES), key="live_attacks", disabled=busy, help="Continuous mode only.")
    controls[4].slider("Events per second", MIN_RATE, MAX_RATE, DEFAULT_RATE, 1.0, key="live_rate", disabled=busy)

    flag_cols = st.columns([1, 1, 2])
    flag_cols[0].checkbox(
        "Rule-based detector",
        value=True,
        key="live_enable_rules",
        disabled=busy,
        help="Evaluates authentication events against security detection rules (e.g. bruteforce, impossible travel).",
    )
    flag_cols[1].checkbox(
        "ML baseline detector",
        value=True,
        key="live_enable_ml",
        disabled=busy,
        help="Scores events with the supervised Random Forest model (prob >= 0.5 flags ML-positive signals).",
    )

    rules_on = st.session_state.get("live_enable_rules", True)
    ml_on = st.session_state.get("live_enable_ml", True)
    if rules_on and ml_on:
        mode_label = "Rules + ML (Full correlation & dual detection)"
    elif rules_on:
        mode_label = "Rules only (Rule alerts & rule-backed cases only)"
    elif ml_on:
        mode_label = "ML only (Event anomaly signals & ML-only cases only)"
    else:
        mode_label = "Neither detector (Ingestion baseline · 0 alerts · 0 cases)"
    flag_cols[2].caption(f"**Detector configuration:** {mode_label}")

    if st.session_state.get("live_error"):
        st.error(st.session_state["live_error"])

    buttons = st.columns(5)
    buttons[0].button("Start", on_click=live_start, disabled=busy, key="live_start", type="primary")
    buttons[1].button("Pause", on_click=live_action, args=("pause",), disabled=state != "running", key="live_pause")
    buttons[2].button("Resume", on_click=live_action, args=("resume",), disabled=state != "paused", key="live_resume")
    buttons[3].button("Stop", on_click=live_action, args=("stop",), disabled=state not in ("running", "paused"), key="live_stop")
    buttons[4].button("Reset", on_click=live_action, args=("reset",), disabled=not busy, key="live_reset")

    if service is None:
        st.info("No simulation is running. Choose a mode and press Start.")
        st.markdown("---")
        _render_live_benchmark_panel()
        return

    st.markdown(f"**Status: {state.upper()}** · {summary['message']}")
    if state == "error":
        st.error(summary["error"])
    if state == "completed":
        st.caption("Stopped or finished. Press Reset to start a new run.")

    active_rules = "ACTIVE" if summary.get("enable_rules") else "DISABLED"
    active_ml = "ACTIVE" if summary.get("enable_ml") else "DISABLED"
    st.caption(
        f"**Active Engines:** Rules: `{active_rules}` · ML: `{active_ml}` ({summary.get('detector_mode', '').replace('_', ' ').title()}) · "
        f"Agents: {summary['agent_mode']} ({summary['provider_id']}) · Simulation `{summary['simulation_id'][:16]}...`"
    )

    st.markdown("##### 1. Operational Ingestion Stream")
    row = st.columns(6)
    row[0].metric("Released", summary["released"])
    row[1].metric("Processed", summary["processed"])
    row[2].metric("Pending", summary["pending"])
    row[3].metric("Simulated time", summary["simulated_time"][11:19] + " UTC" if summary["simulated_time"] else "—")
    row[4].metric("Elapsed", f"{summary['elapsed_seconds']:.0f} s")
    row[5].metric("Effective rate", f"{summary['effective_rate']:g} /s", help=f"Configured {summary['configured_rate']:g} /s")

    st.markdown("##### 2. Detection & Case Triage Pipeline")
    counts = st.columns(5)
    counts[0].metric("Rule alerts", summary["rule_alerts"], help="Incidents triggered by rule engine.")
    counts[1].metric("Open cases", summary["cases_open"], help=f"Cases whose evidence is still in the {summary['retention_hours']:g} h window.")
    counts[2].metric("Investigations", summary["investigations_completed"], help="Cases investigated by deterministic mock agent.")
    counts[3].metric("Tool calls", summary["tool_calls"], help=f"Errors: {summary['tool_errors']}")
    counts[4].metric("ML-only not investigated", summary["ml_only_not_investigated"], help="Session budget for ML-only investigations reached.")

    st.markdown("---")
    st.markdown("### Case Triage & Evidence Workbench")
    cases = service.cases()
    if cases:
        st.dataframe(live_case_rows(service), use_container_width=True, hide_index=True)
        chosen = st.selectbox("Inspect case", [case["case_id"] for case in cases], key="live_case")
        detail = live_case_detail(service, chosen)
        if detail:
            _render_case_dossier(detail)
    else:
        if not summary.get("enable_rules") and not summary.get("enable_ml"):
            st.info("Ingestion baseline active (all detectors disabled). Events are ingested and processed without generating alerts or cases.")
        else:
            st.info("No cases triaged yet. Detection engines are monitoring the incoming event stream.")

    st.markdown("---")
    tab_stream, tab_alerts_live, tab_activity = st.tabs(["Live Event Stream", "Recent Rule Alerts", "Investigation Activity"])
    with tab_stream:
        st.dataframe(list(reversed(service.recent_events())), use_container_width=True, hide_index=True)
    with tab_alerts_live:
        st.dataframe(service.alerts()[:50], use_container_width=True, hide_index=True)
    with tab_activity:
        st.dataframe(service.activity()[:100], use_container_width=True, hide_index=True)

    with st.expander("Engine Observability"):
        st.json(summary, expanded=False)

    st.markdown("---")
    _render_completed_evaluation_section(service, state)
    st.markdown("---")
    _render_live_benchmark_panel()


st.set_page_config(page_title="Login-log anomaly explorer", layout="wide")

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    h1 {
        font-size: 1.75rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        color: #f8fafc !important;
        margin-bottom: 0.2rem !important;
    }
    h2, h3, h4 {
        font-weight: 600 !important;
        letter-spacing: -0.01em !important;
        color: #e2e8f0 !important;
    }
    h5 {
        font-size: 0.85rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        color: #94a3b8 !important;
        margin-top: 1.2rem !important;
        margin-bottom: 0.6rem !important;
    }

    [data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.2);
    }
    [data-testid="stMetricLabel"] {
        font-size: 0.75rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.04em !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
    }
    [data-testid="stMetricValue"] {
        font-size: 1.35rem !important;
        font-weight: 700 !important;
        color: #f1f5f9 !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1f2937;
        padding-bottom: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 4px 4px 0 0;
        padding: 8px 16px;
        font-size: 0.9rem;
        font-weight: 500;
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #60a5fa !important;
        font-weight: 600 !important;
    }

    .stButton > button {
        border-radius: 5px;
        font-weight: 500;
        font-size: 0.85rem;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #1f2937;
        border-radius: 6px;
        overflow: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("Login-log anomaly explorer")
st.caption("Synthetic data only. Labels appear only in sections marked **uses labels**.")

with st.sidebar:
    st.header("Dataset")
    # The browser stores numbers as IEEE doubles, exact only up to 2**53 - 1. The generator
    # accepts seeds up to 2**63 - 1; the UI keeps to the range it can represent exactly.
    seed = st.number_input("Seed", min_value=0, max_value=2**53 - 1, value=31, step=1)
    n_events = st.number_input("Events (n_events)", min_value=1, max_value=200_000, value=1500, step=100)
    n_accounts = st.number_input("Accounts (n_accounts)", min_value=1, max_value=20_000, value=150, step=10)
    duration = st.number_input("Window (hours)", min_value=1, max_value=8784, value=72, step=1)
    st.header("Malicious campaigns")
    bruteforce = st.number_input("Bruteforce", min_value=0, max_value=50, value=2)
    spraying = st.number_input("Password spraying", min_value=0, max_value=50, value=1)
    travel = st.number_input("Impossible travel", min_value=0, max_value=50, value=2)
    travelers = st.number_input("Benign travelers", min_value=0, max_value=50, value=2)

try:
    plan = ScenarioPlan(
        bruteforce_campaigns=int(bruteforce),
        password_spraying_campaigns=int(spraying),
        impossible_travel_campaigns=int(travel),
        benign_travelers=int(travelers),
    )
    session = SessionConfig(
        seed=int(seed), n_events=int(n_events), n_accounts=int(n_accounts), duration_hours=int(duration), plan=plan
    )
except ValueError as error:
    st.error(f"Configuration rejected: {error}")
    st.stop()

tab_live, tab_generate, tab_detect, tab_alerts, tab_eval, tab_agentic, tab_lab = st.tabs(
    ["SOC Live", "Generate", "Detectors", "Alerts", "Evaluation (labels)", "Investigations", "Threat Lab (labels)"]
)

try:
    dataset = events_cached(session)
except ValueError as error:
    # A plan that does not fit the budget or the accounts is a user error, not a crash.
    st.error(f"Generation rejected: {error}")
    st.stop()

workflow = workflow_cached(session)
alerts = list(workflow.rule_alerts)
model_info = baseline_model()
flagged = {signal.event_id: 1 for signal in workflow.ml_positive_signals}

with tab_generate:
    st.write(f"{len(dataset.events)} events, manifest seed {dataset.manifest.seed}, generator {dataset.manifest.generator_version}.")
    st.dataframe(
        [
            {
                "event_id": e.event_id,
                "timestamp_utc": e.timestamp_utc.isoformat(),
                "account_id": e.account_id,
                "source_ip": e.source_ip,
                "outcome": e.outcome.value,
                "country_code": e.country_code,
            }
            for e in dataset.events[:200]
        ],
        use_container_width=True,
    )

with tab_live:
    live_panel()

with tab_detect:
    st.subheader("Rule detector")
    st.write(f"{len(alerts)} alerts.")
    st.dataframe(alert_rows(alerts), use_container_width=True)

    st.subheader("ML baseline")
    _, train_rows, train_positive = model_info
    st.write(
        f"Trained on {train_rows} rows ({train_positive} malicious) from the training seeds. "
        f"Flagged {sum(flagged.values())} events in this dataset."
    )

with tab_alerts:
    if not alerts:
        st.info("No alerts for this dataset. Add campaigns in the sidebar or change the seed.")
    else:
        chosen = st.selectbox("Alert", [a.alert_id for a in alerts])
        alert = next(a for a in alerts if a.alert_id == chosen)
        st.json(explain_alert(alert))
        st.subheader("Related events")
        st.dataframe(related_events(dataset, alert), use_container_width=True)

with tab_eval:
    st.warning("This tab uses ground-truth labels. Detectors never read them.")
    truth = truth_cached(session)
    flagged_sets = {
        "rules": {event_id for alert in alerts for event_id in alert.event_ids},
        "ml": {event_id for event_id, value in flagged.items() if value == 1},
        "all_benign": set(),
    }
    st.dataframe(comparison_rows(truth, flagged_sets), use_container_width=True)
    st.caption("Synthetic data. These numbers do not estimate production performance.")

with tab_agentic:
    st.subheader("Alert investigations")
    st.info(
        "Pipeline: **rules + ML signals → provenance-bound cases → mock bounded investigator → deterministic reviewer**. "
        "The native rule investigator remains the baseline below. Mock mode is local and does not call an LLM."
    )
    st.subheader("Case workbench · label-free runtime")
    st.caption(f"{len(workflow.cases)} cases · mode: mock · dataset {workflow.dataset_id[:18]}…")
    st.dataframe(case_rows(workflow), use_container_width=True, hide_index=True)
    if workflow.cases:
        chosen_case = st.selectbox("Inspect case", [case.case_id for case in workflow.cases], key="agentic_case")
        st.json(case_detail(workflow, chosen_case), expanded=False)
    st.subheader("Native rule-alert baseline")
    investigations = investigations_cached(session)
    summary = investigation_summary(investigations)

    cols = st.columns(6)
    cols[0].metric("Rule alerts", summary["alerts"])
    cols[1].metric("Investigated", summary["investigated"])
    cols[2].metric("Malicious", summary["malicious"])
    cols[3].metric("Benign", summary["benign"])
    cols[4].metric("Inconclusive", summary["inconclusive"])
    cols[5].metric("Failed / limit", f"{summary['failed']} / {summary['limit_reached']}")

    show_eval = st.toggle("Show evaluation against labels (uses labels)", value=True, key="agentic_show_eval")
    evaluations = evaluations_cached(session) if show_eval else None
    if evaluations is not None:
        scored = investigation_summary(investigations, evaluations)["evaluation"]
        with st.container(border=True):
            st.markdown("**Evaluation** · uses labels · scored after the investigation, never fed back to it")
            ecols = st.columns(6)
            ecols[0].metric("Scored", scored["scored"])
            ecols[1].metric("Correct", scored["correct"])
            ecols[2].metric("Incorrect", scored["incorrect"])
            ecols[3].metric("Inconclusive", scored["inconclusive"])
            ecols[4].metric("Unsupported evidence", scored["unsupported_evidence"])
            ecols[5].metric("Policy violations", scored["forbidden_access_attempts"] + scored["tool_limit_violations"])
            st.caption("One synthetic seed. Not evidence of generalization or of production performance.")

    if not investigations:
        st.info("No rule alerts to investigate for this dataset. Add campaigns in the sidebar or change the seed.")
    else:
        st.dataframe(investigation_rows(investigations, evaluations), use_container_width=True, hide_index=True)

        chosen_id = st.selectbox("Inspect alert", [item.alert_id for item in investigations], key="agentic_alert")
        item = next(i for i in investigations if i.alert_id == chosen_id)
        detail = investigation_detail(item, None if evaluations is None else evaluations.get(item.alert_id))

        with st.container(border=True):
            if detail["status"] == "failed":
                st.error(f"Investigation of {detail['alert_id']} failed: {detail['error']}")
            else:
                head = st.columns([2, 1, 1, 1])
                head[0].markdown(f"### {detail['alert_id']} · `{detail['rule']}`\nVerdict: {verdict_badge(detail['verdict'])}")
                head[1].metric("Confidence", f"{detail['confidence']:.2f}")
                budget = detail["budget"]
                head[2].metric("Tool calls", f"{budget['tool_calls']} / {budget['max_tool_calls']}")
                head[3].metric("Steps", f"{budget['steps']} / {budget['max_steps']}")

                if budget["refused_tools"]:
                    st.warning(f"Budget limit reached. Not called: {', '.join(budget['refused_tools'])}.")
                if budget["failed_tools"]:
                    st.error(f"Tool errors: {', '.join(budget['failed_tools'])}.")

                st.markdown("**Justification**")
                st.write(detail["justification"])
                left, right = st.columns(2)
                with left:
                    st.markdown("**Evidence** (alert events only)")
                    st.dataframe(detail["evidence"], use_container_width=True, hide_index=True)
                with right:
                    st.markdown("**Tool calls** (read-only, audited)")
                    st.dataframe(detail["tool_calls"], use_container_width=True, hide_index=True)
                if detail["limitations"]:
                    st.markdown("**Limitations**")
                    for text in detail["limitations"]:
                        st.markdown(f"- {text}")

            if evaluations is not None:
                st.markdown("**Evaluation** · uses labels")
                if detail["evaluation"] is None:
                    st.info("Not scored: the investigation did not complete.")
                else:
                    st.json(detail["evaluation"], expanded=False)

    with st.expander("Component status"):
        st.dataframe(list(COMPONENT_STATUS), use_container_width=True, hide_index=True)
    with st.expander("Evaluator test fixtures (simulated, not investigations)"):
        st.caption("Simulated: hand-written cases checked by the test suite to validate the evaluator.")
        st.table([{"case": case, "expected behavior": behavior} for case, behavior in AGENTIC_FIXTURES])
        st.caption("Design and contracts: docs/agentic-evaluators.md")

with tab_lab:
    # Fixed scenario catalog on fixed Threat Lab seeds (not the sidebar dataset).
    st.warning("Scenario results use ground-truth labels for scoring. Detectors never read them.")
    st.info("Each scenario runs the same label-free workflow. Labels score results only after runtime cases and investigations complete.")
    lab = lab_cached()
    st.subheader("Scenario catalog")
    st.dataframe(catalog_rows(build_catalog()), use_container_width=True, hide_index=True)
    st.subheader("Rules versus ML, per scenario")
    st.caption(
        "`rules_fp` and `ml_fp` count benign events flagged. `false_positive_alerts` counts rule alerts "
        "with no malicious event. These are different counts."
    )
    st.dataframe(lab_comparison_rows(lab), use_container_width=True, hide_index=True)

    st.subheader("Mock scenario proposal")
    st.caption("A mock scenario agent proposes a fixed-schema spec. It is validated before it runs; no code is executed.")
    try:
        proposed = proposal_cached()
    except ScenarioProposalError as error:
        st.error(f"Proposal rejected: {error}")
    else:
        st.dataframe(lab_comparison_rows(proposed), use_container_width=True, hide_index=True)

    chosen_scenario = st.selectbox("Scenario", [item["scenario"]["scenario_id"] for item in lab["scenarios"]], key="lab_scenario")
    scenario = next(item for item in lab["scenarios"] if item["scenario"]["scenario_id"] == chosen_scenario)
    detail = scenario_detail(scenario)
    st.markdown(f"**{scenario['scenario']['description']}**")
    st.dataframe(detail["per_seed"], use_container_width=True, hide_index=True)
    if detail["false_positive_alerts"]:
        st.dataframe(detail["false_positive_alerts"], use_container_width=True, hide_index=True)
    else:
        st.info("No false-positive alerts in this scenario.")
    with st.expander("Threat Lab limitations"):
        for text in lab["limitations"]:
            st.markdown(f"- {text}")
    st.caption("Few seeds per scenario. These numbers are not evidence of generalization or of production performance.")
