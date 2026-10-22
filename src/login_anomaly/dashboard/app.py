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
    events_for,
    explain_alert,
    investigation_detail,
    investigation_rows,
    investigation_summary,
    investigations_for,
    ml_flags,
    related_events,
    rule_alerts,
)
from login_anomaly.evaluation.experiment import train_baseline
from login_anomaly.evaluation.investigation import evaluate_investigations
from login_anomaly.evaluation.panel import comparison_rows, truth_for
from login_anomaly.simulation.scenarios import ScenarioPlan

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


@st.cache_resource(show_spinner="Running the rule detector...")
def alerts_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return rule_alerts(events_cached(session))


@st.cache_resource(show_spinner="Scoring events with the ML baseline...")
def ml_flags_cached(session: SessionConfig) -> dict[str, int]:
    return ml_flags(baseline_model()[0], events_cached(session))


@st.cache_resource(show_spinner="Investigating rule alerts...")
def investigations_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    # Observable events and rule alerts only. No labels reach the investigator.
    return investigations_for(events_cached(session), alerts_cached(session))


@st.cache_resource(show_spinner="Generating events and labels for the evaluation panel...")
def truth_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return truth_for(session.seed, session.n_events, session.n_accounts, session.duration_hours, session.plan)


@st.cache_resource(show_spinner="Scoring investigations against labels...")
def evaluations_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return evaluate_investigations(investigations_cached(session), truth_cached(session).ground_truth)


def verdict_badge(verdict: str | None) -> str:
    return f":{VERDICT_COLORS.get(verdict or '', 'gray')}[**{verdict or 'n/a'}**]"


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

tab_generate, tab_detect, tab_alerts, tab_eval, tab_agentic = st.tabs(
    ["Generate", "Detectors", "Alerts", "Evaluation (labels)", "Investigations"]
)

try:
    dataset = events_cached(session)
except ValueError as error:
    # A plan that does not fit the budget or the accounts is a user error, not a crash.
    st.error(f"Generation rejected: {error}")
    st.stop()

alerts = alerts_cached(session)
model_info = baseline_model()
flagged = ml_flags_cached(session)

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
        "Pipeline: **rule alerts → deterministic investigator → agentic evaluator**. "
        "The investigator is rule-based (no LLM) and reads observable events only through read-only tools. "
        f"ML flags ({sum(flagged.values())} events) are **not investigated**: there is no ML-to-investigator integration yet."
    )
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
