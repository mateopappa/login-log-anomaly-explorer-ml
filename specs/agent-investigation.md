# agent-investigation

The case investigator proposes a verdict from observable events. This story says what is already true, and how a script proves it. It does not claim that Haiku is better than the mock. That claim needs a person, and it is not a criterion here.

## Roles

- Producer: `MockInvestigatorProvider` proposes the verdict. Haiku is an optional adapter and is not evidence in CI.
- Reviewer: `review_case_investigation` checks policy (tools, budget, evidence shape) and never sees labels.
- Judge: `evaluate_investigation` scores a finished result against labels, after the run, in another module.

## Invariants

- Investigator code and its tools do not import ground truth or `login_anomaly.evaluation`.
- A malicious verdict without evidence is a finding, not a pass.
- CI does not call Anthropic.

## Criteria

- AC-GT | script | tests/test_ground_truth_isolation.py::test_no_module_outside_simulation_imports_ground_truth
- AC-RUNTIME | script | tests/test_ground_truth_isolation.py::test_runtime_modules_cannot_reach_labels_through_evaluation
- AC-TOOLS | fixture | tests/test_agentic_tools.py::test_registry_matches_the_documented_read_only_tools
- AC-JUSTIFICATION | fixture | tests/test_agentic_contracts.py::test_result_requires_non_empty_justification
- AC-EVIDENCE | fixture | tests/test_agentic_contracts.py::test_evidence_must_be_references_not_free_text
- AC-DENY | fixture | tests/test_case_investigator.py::test_forbidden_or_malformed_tool_request_is_denied
- AC-BUDGET | fixture | tests/test_case_investigator.py::test_tool_and_step_budgets_stop_the_loop
- AC-REVIEW | fixture | tests/test_case_investigator.py::test_review_flags_zero_confidence_verdict_and_policy_findings
- AC-JUDGE | judge | tests/test_agentic_evaluator.py::test_insufficient_evidence_is_reported_as_a_finding
- AC-NO-LABELS | judge | tests/test_agentic_evaluator.py::test_ground_truth_access_attempt_is_counted_as_forbidden

Close this story with `.venv/bin/python scripts/check_story.py specs/agent-investigation.md`. A green node is the evidence for that line. A human signature, when one is required, is written `signed: NAME — reason`.
