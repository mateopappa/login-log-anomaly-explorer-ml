---
name: verify
description: Verify the current implementation by running the project's own configured tests, lint, type checks, and format checks, targeted first and broader after. Reports passed, failed, skipped, and not-run checks honestly. Use only when the user explicitly invokes /verify.
disable-model-invocation: true
---

Verify the current state of the repository.

## 1. Discover the real commands

- Look for test, lint, type, and format configuration in `pyproject.toml`, `setup.cfg`, `tox.ini`, `pytest.ini`, `Makefile`, and `.github/workflows/`.
- Run only commands that the project defines. Do not invent a command for a tool that is not configured.
- If a category has no configuration, report it as `NOT CONFIGURED` and move on. As of this setup, the repository has no configured tooling.

## 2. Run targeted checks first

- Identify changed files with `git status` and `git diff --name-only`.
- Run the tests that cover those files first.
- Then run the full local test suite, lint, type check, and format check, all in check-only mode. Do not auto-fix formatting.

## 3. Review the checks themselves

- Confirm that changed behavior has regression coverage.
- Confirm that input validation and error handling exist at the boundaries that changed.
- Confirm that interface contracts (function signatures, API schemas) are unchanged, or that any change is intentional and reported.

## 4. Rules you must follow

- Never edit code or tests to make a check pass. Never delete, skip, or mark a test as expected-failure to hide a failure.
- If a failure already existed before the change, say so and give the evidence you have. Do not claim it is unrelated without checking.
- Do not call the Codex API or any external service. ML evaluation belongs to `/evaluate-ml`, not here.
- Do not print environment variables or anything from `.env` files.

## 5. Report

Give one row per check:

| Check | Command | Status | Key output |
| :- | :- | :- | :- |

Use exactly these statuses:
- `PASSED`: the command ran and exited 0.
- `FAILED`: the command ran and exited non-zero. Include the failing test names or error lines.
- `SKIPPED`: the check exists but was not run, with the reason.
- `NOT CONFIGURED`: no command exists for this check.

Never write PASSED for a check that did not run. End with a single overall verdict: `VERIFIED`, `FAILED`, or `INCOMPLETE`. Use `INCOMPLETE` when any check is not configured or not run.
