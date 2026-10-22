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
    related_events,
    scenario_detail,
    workflow_for,
)
from login_anomaly.evaluation.experiment import train_baseline
from login_anomaly.evaluation.investigation import evaluate_investigations
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
    elif st.session_state.get(LIVE_KEY) is not None:
        getattr(st.session_state[LIVE_KEY], name)()


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
        return
    st.markdown(f"**Status: {state.upper()}** · {summary['message']}")
    if state == "error":
        st.error(summary["error"])
    if state == "completed":
        st.caption("Stopped or finished. Press Reset to start a new run.")

    row = st.columns(6)
    row[0].metric("Released", summary["released"])
    row[1].metric("Processed", summary["processed"])
    row[2].metric("Pending", summary["pending"])
    row[3].metric("Simulated time", summary["simulated_time"][11:19] + " UTC" if summary["simulated_time"] else "—")
    row[4].metric("Elapsed", f"{summary['elapsed_seconds']:.0f} s")
    row[5].metric("Effective rate", f"{summary['effective_rate']:g} /s", help=f"Configured {summary['configured_rate']:g} /s")
    counts = st.columns(5)
    counts[0].metric("Rule alerts", summary["rule_alerts"])
    counts[1].metric("Open cases", summary["cases_open"], help=f"Cases whose evidence is still in the {summary['retention_hours']:g} h window.")
    counts[2].metric("Investigations", summary["investigations_completed"])
    counts[3].metric("Tool calls", summary["tool_calls"], help=f"Errors: {summary['tool_errors']}")
    counts[4].metric("ML-only not investigated", summary["ml_only_not_investigated"], help="Session budget for ML-only investigations reached.")
    st.caption(f"Agents: {summary['agent_mode']} ({summary['provider_id']}). Simulation {summary['simulation_id']}.")

    st.markdown("**Live event stream** (latest first, observable fields only)")
    st.dataframe(list(reversed(service.recent_events())), use_container_width=True, hide_index=True)
    st.markdown("**Recent alerts**")
    st.dataframe(service.alerts()[:50], use_container_width=True, hide_index=True)
    st.markdown("**Cases**")
    cases = service.cases()
    st.dataframe(cases, use_container_width=True, hide_index=True)
    if cases:
        chosen = st.selectbox("Inspect case", [case["case_id"] for case in cases], key="live_case")
        st.json(live_case_detail(service, chosen), expanded=False)
    st.markdown("**Investigation activity**")
    st.dataframe(service.activity()[:100], use_container_width=True, hide_index=True)
    with st.expander("Observability"):
        st.json(summary, expanded=False)


st.set_page_config(page_title="Login-log anomaly explorer", layout="wide")
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

tab_generate, tab_live, tab_detect, tab_alerts, tab_eval, tab_agentic, tab_lab = st.tabs(
    ["Generate", "SOC Live", "Detectors", "Alerts", "Evaluation (labels)", "Investigations", "Threat Lab (labels)"]
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
