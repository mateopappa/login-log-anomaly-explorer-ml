# AI-assisted development workflow

This project uses Claude Code with a small set of project-scoped skills and
subagents. The rules that govern the project are in `CLAUDE.md`; this file
explains how to use the workflow tooling.

## Files

```text
.claude/
├── settings.json              # shared permissions (committed)
├── settings.local.json        # personal overrides (git-ignored, optional)
├── agents/
│   ├── architecture-researcher.md   # read-only, sonnet
│   ├── test-reviewer.md             # read-only, haiku
│   └── security-reviewer.md         # read-only, sonnet
└── skills/
    ├── plan-feature/SKILL.md
    ├── implement-task/SKILL.md
    ├── verify/SKILL.md
    ├── review/SKILL.md
    ├── evaluate-ml/SKILL.md
    └── tdd/                       # local adaptation of mattpocock/skills, see SKILL.md header
        ├── SKILL.md
        ├── tests.md               # unchanged upstream
        └── mocking.md             # unchanged upstream
```

## Workflow

Work in this order. Each step has its own command, so you can stop at any point.

1. `/plan-feature <description>`: inspects the code and returns a plan with
   acceptance criteria and regression tests. It edits nothing and waits for you.
2. Approve the plan in plain words, naming the steps you accept.
3. `/implement-task <approved step>`: makes the change and its tests. It does
   not commit.
4. `/verify`: runs the project's configured checks and reports each one as
   `PASSED`, `FAILED`, `SKIPPED`, or `NOT CONFIGURED`.
5. `/review`: read-only review of the diff, by severity. Apply fixes only when
   you ask.
6. Commit yourself when you are satisfied.

`/evaluate-ml` is separate. Run it only when a detector or dataset has changed
and you want a new comparison, not during ordinary development.

## Skills

All project skills are invoked only by you (`disable-model-invocation: true`).
Claude does not start them on its own, so they cannot spend API budget or edit
files without a request.

| Command | Purpose | Edits files? |
| :- | :- | :- |
| `/plan-feature` | Plan before implementing; stop for approval | No |
| `/implement-task` | Implement one approved, bounded task with tests | Yes |
| `/verify` | Run configured tests, lint, and type checks | No |
| `/review` | Critical review of a diff or branch | No |
| `/evaluate-ml` | Plan or run a reproducible detector comparison | Writes result files only |
| `/tdd` | Red → green reference for a test-first slice, one approved seam at a time | Yes, with the task |

The skill definitions are in `.claude/skills/<name>/SKILL.md`. Edit them there,
not in this document.

## Subagents

Delegate only when a second, independent read helps. Each subagent is read-only
and has no shell access.

| Agent | Model | Use it for |
| :- | :- | :- |
| `architecture-researcher` | sonnet | Comparing design options against `CLAUDE.md` |
| `test-reviewer` | haiku | Finding missing edge cases, weak assertions, and flaky tests |
| `security-reviewer` | sonnet | Input validation, injection, agent tool scope, ground-truth leakage |

How to invoke one:
- Say it in plain words: "Use the security-reviewer subagent on the parser changes."
- Or @-mention it: `@"security-reviewer (agent)" check the investigator tools`.

Give a subagent the files or diff and the question. Do not give it your
conclusion, and do not let two agents edit the same files.

## Settings and permissions

`.claude/settings.json` is committed and contains only:
- **allow**: read-only git commands (`status`, `diff`, `log`, `show`).
- **ask**: commits, pushes, resets, checkouts, `rm`, `curl`, and `wget`. Each one
  prompts before it runs.
- **deny**: `rm -rf`, `sudo`, and reading `.env`, `.env.local`, and `.env.*.local`.

Permission rules are a guardrail, not a sandbox. They match command text, so
they can be bypassed by an unusual command form. Review anything unexpected in
the prompt before approving.

No API keys, tokens, or credentials are stored in any settings file. Keep them
in environment variables. `.env` files are git-ignored.

## Hooks: deferred

No hooks are configured. pytest is available, but a full run takes several
seconds because it includes the experiment tests, which is too slow for a
`PostToolUse` hook. Add a hook only for a fast, targeted check, and keep it
cheap: no LLM calls and no broad commands.

## Third-party skills and tools

One third-party skill is adopted: `tdd`, a local copy of `mattpocock/skills`
(MIT), pinned to commit `5beb35b` in its header and changed for this project
(`disable-model-invocation: true` added). No skill is installed from a registry.
Caveman and Junior to Senior were evaluated and not installed. Before adding any
third-party skill, check its source, license, requested permissions, and the
code it runs, then ask for approval.

Python dependencies are declared in `pyproject.toml`: `pytest` (dev), `scikit-learn`
(extra `ml`, for the baseline), and `streamlit` (extra `dashboard`, for the app).
The generator and the rule detector need no third-party runtime package.

## Verifying a task

- Use `/verify` for the configured checks. It reports only what actually ran.
- Read the `NOT CONFIGURED` and `SKIPPED` rows. They are gaps, not passes.
- For an ML change, run `/evaluate-ml` and check the pre-run checklist first.
- Do not treat a passing test suite as proof of a security property. Use
  `/review` and the `security-reviewer` subagent for that.

## Budget

- Routine work runs on Haiku. Use Sonnet only for architecture, security, and
  other hard reasoning.
- Ordinary tests are local and deterministic. Claude API calls belong only to
  the application's investigator path, not to development or tests.
- Do not run large LLM evaluations after each edit.

## Open items

- Tests: pytest is configured (`pyproject.toml`) and runs in CI
  (`.github/workflows/ci.yml`). Lint, type checking, and formatting are not
  configured, so `/verify` reports those as `NOT CONFIGURED` and its verdict is
  `INCOMPLETE`, not `VERIFIED`.
- Agentic Evaluators are designed in `docs/agentic-evaluators.md`. The
  investigator is not implemented, so no skill or command runs one.
