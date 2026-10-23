---
name: review
description: Critically review a proposed diff or implementation for correctness, security, maintainability, unnecessary complexity, and regressions. Reports findings by severity with file and line references. Read-only; does not edit files. Use only when the user explicitly invokes /review.
argument-hint: "[branch, commit, or path; default is uncommitted changes]"
disable-model-invocation: true
allowed-tools: Read Grep Glob
---

Review target: $ARGUMENTS

This review is read-only. Do not edit, create, or delete files, and do not apply fixes unless the user asks after the review.

## 1. Gather the diff

- If the target is empty, review uncommitted changes: use `git status`, `git diff`, and `git diff --staged`.
- If the target is a branch, commit, or path, use `git diff <target>`.
- For each changed function or class, read the full surrounding code. A diff without its context is not enough to judge it.

## 2. Check

- **Correctness**: logic errors, off-by-one errors, unhandled `None` or empty input, wrong exception handling, race conditions.
- **Security**: untrusted event fields or emails reaching instructions, queries, or commands. Missing input validation at ingestion or API boundaries. Secrets in code or logs. Agent tools broader than their stated purpose.
- **Data and ML integrity**: ground-truth labels reachable from detector or investigator code. Train/test leakage. Missing seeds or unrecorded dataset versions. Rules and ML coupled in a way that creates hybrid scoring.
- **Regressions**: public interfaces changed without need. Behavior changed outside the stated scope.
- **Tests**: changed behavior without coverage, weak assertions, nondeterminism.
- **Complexity**: abstractions with one caller, unused parameters, duplicated logic, dependencies that are not needed.

For a security-sensitive or large diff, you may ask the `security-reviewer` or `test-reviewer` subagent for an independent read. Give it the diff and the relevant files, not your conclusions.

## 3. Report

Order findings by severity: **Critical**, **High**, **Medium**, **Low**, **Nit**. For each finding give:
- The file and line, as `path:line`.
- The defect, with a concrete input or state that triggers it.
- The impact.
- The concrete fix, described in a sentence or a short snippet.

Then add:
- **Not reviewed**: anything you could not read or check.
- **Verdict**: `APPROVE`, `APPROVE WITH CHANGES`, or `REQUEST CHANGES`.

If there are no findings, say so and list what you checked. Do not invent findings to make the review look thorough.
