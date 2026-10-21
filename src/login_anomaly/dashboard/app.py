"""Local Streamlit app. Run: streamlit run src/login_anomaly/dashboard/app.py

It renders what ``dashboard.view`` and ``evaluation.panel`` compute. It contains no
detection logic. Synthetic data only.
"""

from __future__ import annotations

import streamlit as st

from login_anomaly.dashboard.view import (
    SessionConfig,
    alert_rows,
    events_for,
    explain_alert,
    ml_flags,
    related_events,
    rule_alerts,
)
from login_anomaly.evaluation.experiment import train_baseline
from login_anomaly.evaluation.panel import comparison_rows, truth_for
from login_anomaly.simulation.scenarios import ScenarioPlan

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


@st.cache_resource(show_spinner="Training the ML baseline on the training seeds...")
def baseline_model() -> tuple[object, int, int]:
    return train_baseline()


@st.cache_resource(show_spinner="Generating events...")
def events_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return events_for(session)


@st.cache_resource(show_spinner="Generating events and labels for the evaluation panel...")
def truth_cached(session: SessionConfig):  # type: ignore[no-untyped-def]
    return truth_for(session.seed, session.n_events, session.n_accounts, session.duration_hours, session.plan)


st.set_page_config(page_title="Login-log anomaly explorer", layout="wide")
st.title("Login-log anomaly explorer")
st.caption("Synthetic data only. Labels appear only in the evaluation tab.")

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
    ["Generate", "Detectors", "Alerts", "Evaluation (labels)", "Agentic (simulated)"]
)

try:
    dataset = events_cached(session)
except ValueError as error:
    # A plan that does not fit the budget or the accounts is a user error, not a crash.
    st.error(f"Generation rejected: {error}")
    st.stop()

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
    alerts = rule_alerts(dataset)
    st.write(f"{len(alerts)} alerts.")
    st.dataframe(alert_rows(alerts), use_container_width=True)

    st.subheader("ML baseline")
    model, train_rows, train_positive = baseline_model()
    flagged = ml_flags(model, dataset)
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
    st.warning("Simulated. No investigator is implemented. These are fixture cases checked by the test suite.")
    st.table([{"case": case, "expected behavior": behavior} for case, behavior in AGENTIC_FIXTURES])
    st.caption("Design and contracts: docs/agentic-evaluators.md")
