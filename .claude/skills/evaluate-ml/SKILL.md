---
name: evaluate-ml
description: Plan or run a controlled, reproducible comparison of the independent rule-based and supervised ML detectors on identical held-out scenarios. Checks seeds, dataset versions, labels, and leakage, and reports precision, recall, F1, confusion matrices, and limitations. Use only when the user explicitly invokes /evaluate-ml.
argument-hint: "[plan | run] [experiment name]"
disable-model-invocation: true
---

Run this evaluation step: $ARGUMENTS

If no mode is given, plan only.

## 1. Inspect the project first

- Read the detector, dataset generator, split logic, and any existing evaluation code.
- Do not introduce an evaluation framework until the existing structure is known and the user has approved the design. Prefer a small deterministic script over a new library.

## 2. Pre-run checklist

Confirm each item and report any that fail. Do not run until the blocking ones pass.
- The dataset version is recorded (generator version, seed, and a content hash).
- The seed for generation and for any training is fixed and recorded.
- The train and test sets are split by scenario or campaign. No test scenario appears in training.
- Rules and ML are scored on the same held-out scenarios.
- Ground-truth labels are not imported or reachable from detector or investigator code. Check the import graph, not only the function signatures.
- Any threshold or hyperparameter was chosen on a validation split, not on the test split. If the test split was used for tuning, say so in the report.

## 3. Run

- Run locally and deterministically. Do not call the Claude API or any external service.
- Write results to a machine-readable file, such as JSON, that records: seed, dataset version, code version (Git commit), detector configuration, and metrics. Do not overwrite a previous result file without saying so.
- Do not repeat full runs without a reason. Each run should answer a question.

## 4. Report

For each detector, on the same held-out set:
- Precision, recall, and F1.
- Confusion matrix (TP, FP, TN, FN).
- The false positives and false negatives, by scenario ID, with a short note on each group.
- Per-scenario breakdown, to show whether the result comes from a few scenarios.

Then state:
- **Comparison**: which detector did better on which measure. Say that a difference is within noise if the sample is small or results vary across seeds. Do not claim superiority without the numbers that show it.
- **Limitations**: sample size, synthetic-data bias, scenario coverage, and anything the checklist could not confirm.

Report only what the run produced. Never fill in or estimate a metric.
