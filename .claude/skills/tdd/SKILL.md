---
name: tdd
description: Test-driven development reference for red → green loops. Use only when the user explicitly invokes /tdd. Local adaptation of mattpocock/skills (MIT).
argument-hint: "<feature or bug to build test-first>"
disable-model-invocation: true
---

> Local adaptation. Source: https://github.com/mattpocock/skills/tree/5beb35b040e3de97e54fa9e386d7e42d15c295c2/skills/engineering/tdd (MIT), fetched at commit `5beb35b040e3de97e54fa9e386d7e42d15c295c2`.
> Changes from upstream: `disable-model-invocation: true` added; references to the `codebase-design` and `code-review` skills replaced with this project's equivalents; the project constraints section added. `tests.md` and `mocking.md` are unchanged. Their examples are TypeScript; the principles apply to this project's Python and pytest code.

# Test-Driven Development

TDD is the red → green loop. This skill is the reference that makes that loop produce tests worth keeping: what a good test is, where tests go, the anti-patterns, and the rules of the loop. Every section applies on every cycle: consult them before and during the loop, not after.

When exploring the codebase, read `GLOSSARY.md` (if it exists) so test names and interface vocabulary match the project's domain language, and respect ADRs in the area you're touching.

## What a good test is

Tests verify behavior through public interfaces, not implementation details. Code can change entirely; tests shouldn't. A good test reads like a specification: "user can checkout with valid cart" tells you exactly what capability exists, and it survives refactors because it doesn't care about internal structure.

See [tests.md](tests.md) for examples and [mocking.md](mocking.md) for mocking guidelines.

## Seams: where tests go

A **seam** is the public boundary you test at: the interface where you observe behavior without reaching inside. Tests live at seams, never against internals.

**Test only at pre-agreed seams.** Before writing any test, write down the seams under test and confirm them with the user. No test is written at an unconfirmed seam. You can't test everything, so agreeing the seams up front is how testing effort lands on the critical paths and complex logic instead of every edge case.

Ask: "What's the public interface, and which seams should we test?" Give each proposed seam a one-line note on what it catches and what it misses.

When the shape of that interface is itself in question (how deep the module is, where the seam belongs, what the interface should expose), discuss it with the user using the terms module, interface, seam, and adapter. This project has no separate design-vocabulary skill.

## Anti-patterns

- **Implementation-coupled**: mocks internal collaborators, tests private methods, or verifies through a side channel (querying the database instead of using the interface). The tell: the test breaks when you refactor but behavior hasn't changed.
- **Tautological**: the assertion recomputes the expected value the way the code does (`expect(add(a, b)).toBe(a + b)`, a snapshot derived by hand the same way, a constant asserted equal to itself), so it passes by construction and can never disagree with the code. Expected values must come from an independent source of truth: a known-good literal, a worked example, the spec.
- **Horizontal slicing**: writing all tests first, then all implementation. Bulk tests verify _imagined_ behavior: you test the _shape_ of things rather than user-facing behavior, the tests go insensitive to real changes, and you commit to test structure before understanding the implementation. Work in **vertical slices** instead: one test → one implementation → repeat, each test a **tracer bullet** that responds to what the last cycle taught you.

## Rules of the loop

- **Red before green.** Write the failing test first, then only enough code to pass it. Don't anticipate future tests or add speculative features.
- **One slice at a time.** One seam, one test, one minimal implementation per cycle.
- **Refactoring is not part of the loop.** It belongs to the review stage (this project's `/review`, which is read-only), not the red → green implementation cycle.

## Project constraints

These come from this project's `CLAUDE.md` and override anything above:

- Implement only the approved scope. A TDD cycle does not authorize extra features or unrelated changes.
- Run only commands the project configures. Report each test run with its real exit status. Never mark a test as skipped or expected-to-fail to hide a failure.
- Keep ground-truth labels out of anything a detector or investigator can import.
- Do not commit. The user commits.
