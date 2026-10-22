# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0-mvp] - 2026-10-22

### SOC MVP — Functional Baseline

Initial functional MVP pre-release of Login Log Anomaly Explorer.

#### Features
- **Synthetic Authentication Datasets**: Deterministic, reproducible authentication logs with separate ground-truth labeling.
- **Dual Detection Engines**: Explainable rule-based detectors (bruteforce, password spraying, impossible travel) and an independent supervised Random Forest ML baseline.
- **Correlation & Case Management**: Exact event-id association of rule alerts and ML-positive signals into rule-backed and ML-only investigation cases.
- **Bounded Investigator Workflow**: Read-only, bounded investigative agent loop with strict tool policy enforcement.
- **Independent Investigation Review**: Deterministic reviewer verifying citations, confidence calibration, policy compliance, and uncertainty statements.
- **Threat Lab**: Reproducible adversarial evaluation catalog and validated scenario proposal schema.
- **SOC Live Simulation**: Interactive simulation engine featuring both deterministic scenario replay and chunked continuous generation, defaulting to 5 events per second.
- **Interactive SOC Workbench**: Streamlit dashboard for end-to-end dataset generation, detection inspection, case investigation, and live simulation feeds.

#### Known Limitations
- **Preliminary UI**: Current UI is built on Streamlit; a modern SPA redesign is planned.
- **Mock Agent Execution**: All agent roles (Investigator, Reviewer, Proposer) use mock or deterministic execution; real LLM providers are not yet integrated.
- **Baseline ML**: The supervised model is a baseline with documented false-positive and false-negative trade-offs; results reflect synthetic boundaries rather than production generalization.
- **Investigation Capping**: ML-only case investigations are capped at 25 per session to bound execution noise.
- **Independent Continuous Chunks**: Continuous live simulation operates on independent chunks; user and IP state does not persist across chunk boundaries.
- **Synthetic Scope**: Designed and evaluated solely on synthetic authentication logs; not a production SIEM.
- **Deployment**: Distributed ingestion, streaming infrastructure, and Kubernetes deployment remain future work.
