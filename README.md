# Login-log anomaly explorer

A local, reproducible prototype for detecting suspicious authentication activity in **synthetic** login logs. It generates labelled traffic, runs a rule detector and an ML baseline independently, compares them against ground truth, and shows the results in a local dashboard. An agentic investigator and evaluator are **designed** in `docs/agentic-evaluators.md`, not implemented.

Read `docs/agentic-evaluators.md` for the status of each component before drawing conclusions.

## Install

Python 3.11 or newer.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev,ml,dashboard]"
```

Extras: `dev` (pytest), `ml` (scikit-learn, for the baseline), `dashboard` (Streamlit). The generator, the rule detector, and the contracts need no third-party runtime packages.

## Test

```bash
.venv/bin/python -m pytest -v
```

No external service is called. No LLM is called. The suite takes a few seconds.

## Run the experiment

Trains the ML baseline on four generated datasets and evaluates on two others, with the rule detector and a trivial baseline on the same held-out rows.

```bash
.venv/bin/python -m login_anomaly.evaluation.experiment --out reports/experiment.json
```

Results are written to `reports/experiment.json`. The file is deterministic: the same command gives byte-identical output. It is committed as the reviewed artifact; regenerate it only when the experiment changes. All numbers are synthetic, from 2 seeds (nominal sets) or 3 seeds (boundary stress set) per evaluation set, and the model is trained on 4 training seeds. Read the `limitations` field before quoting any number.

## Run the dashboard

```bash
.venv/bin/python -m streamlit run src/login_anomaly/dashboard/app.py
```

Tabs: generate events, run the detectors, explore alerts with their evidence, compare against labels (evaluation only), and investigations: every rule alert investigated by the deterministic investigator (no LLM), with an optional evaluation against labels. ML flags are not investigated yet. The Threat Lab tab (labels) runs the scenario catalog on fixed seeds and compares rules and ML per scenario; its alerts are not sent to the investigator yet.

## Layout

```
src/login_anomaly/
  events.py              AuthEvent contract (observable fields only)
  validation.py          shared validation helpers
  simulation/            generator, scenarios, ground truth, manifest, config
  detection/rules.py     rule detector (events only)
  ml/                    causal features and the baseline model (events only)
  evaluation/            metrics, experiment, evaluation panel, agentic evaluator
  agentic/contracts.py   investigator/evaluator contracts and tool policy
  dashboard/             view logic (no Streamlit) and the Streamlit app
docs/agentic-evaluators.md   design, diagram, contracts, status
```

## Ground-truth boundary

Labels exist only in `simulation/ground_truth.py` and are returned only by `generate_with_truth()`. A static test (`tests/test_ground_truth_isolation.py`) fails if any module outside `simulation/` and `evaluation/` imports the ground-truth module or the truth-bearing names. This is a structural guard. It does not catch dynamic imports, and it is not a runtime security boundary.

## Limitations

- Synthetic data only. The nominal set shares its thresholds with the rule detector, so its rule scores are optimistic by construction (rules F1 0.964, ML 0.990).
- With benign decoys (everyday look-alikes, assumed not measured), precision drops for both methods: rules F1 0.79, ML 0.78. Most false alarms come from a shared office address that spraying rules flag, and from roaming logins that travel rules flag.
- The boundary stress set sits just outside the rule thresholds by design. It shows how fast rules fail at their edge (rules F1 0.01, ML 0.70). It is not evidence of generalization. A real shift test (different attacker behaviour, far from the thresholds) is future work.
- The ML baseline was trained on the nominal specification only. None of these numbers estimates performance on real logs, and 2 or 3 seeds per evaluation set are too few to rank the methods with confidence.
- The dashboard seed control stops at 2^53-1, the largest integer a browser number holds exactly. The generator accepts up to 2^63-1.
- The agentic investigator does not exist. The agentic evaluator is checked with hand-written fixtures.
