---
name: plan-feature
description: Plan a feature or bug fix before any implementation code changes. Produces goal, assumptions, risks, smallest viable implementation, acceptance criteria, and regression tests, then stops for approval. Use only when the user explicitly invokes /plan-feature.
argument-hint: "<feature or bug description>"
disable-model-invocation: true
allowed-tools: Read Grep Glob
---

Plan this change: $ARGUMENTS

This is a planning step. Do not edit, create, or delete any file, and do not run tests or install anything.

1. Apply the constraints in `CLAUDE.md`. Read it if it is not already in context.
2. Run `git status` and note uncommitted changes. The plan must not depend on or overwrite them.
3. Inspect the relevant files, interfaces, and tests. If the repository has little or no code yet, say so and plan from `CLAUDE.md` and existing docs. Do not invent code that is not there.
4. Return the plan in this structure:
   - **Goal**: one or two sentences.
   - **Non-goals**: what this change will not do.
   - **Assumptions**: each one stated, with the conservative choice made. Mark any that need confirmation.
   - **Risks**: security (untrusted input, ground-truth leakage, agent tool scope), reproducibility (seeds, dataset versions), API cost, and time.
   - **Smallest viable implementation**: numbered steps, each small enough to review on its own.
   - **Files likely to change**: and any change to a public interface, flagged explicitly.
   - **Acceptance criteria**: objective and testable.
   - **Regression tests**: test names and the assertion each one makes. If no test runner is configured yet, say so and list setup as a separate step.
   - **Verification**: only commands that exist in the repository. If none exist, write "not configured" and do not guess a command.
   - **Blocking questions**: only those that change the plan. Leave out questions the plan can answer with a stated assumption.
5. Stop after the plan. Do not start implementation. Implementation begins only when the user approves, for example with `/implement-task`.
