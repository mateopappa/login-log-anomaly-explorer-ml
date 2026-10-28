"""Close a story only when every criterion has evidence a script can re-run.

shortcut: a green pytest node is accepted as evidence for that line; the script does not read the test body. Upgrade when a named test passes without asserting its criterion.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KINDS = {"script", "fixture", "judge", "human"}
CRITERION = re.compile(r"^- ([A-Z][A-Z0-9-]*) \| (script|fixture|judge|human) \| ?(.*)$")
NODE = re.compile(r"^tests/[A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_\[\]-]+)?$")
SIGNED = re.compile(r"^signed:\s*(\S+)\s+[—-]\s+(\S.*)$")
MODEL_RUN = re.compile(r"haiku|anthropic", re.IGNORECASE)


def parse_criteria(text: str) -> list[tuple[str, str, str]]:
    lines = text.splitlines()
    start = next((i + 1 for i, line in enumerate(lines) if line.strip() == "## Criteria"), None)
    if start is None:
        raise ValueError("no criteria")
    found: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for line in lines[start:]:
        if line.startswith("## "):
            break
        stripped = line.strip()
        if not stripped or not stripped.startswith("- "):
            continue
        match = CRITERION.match(stripped)
        if match is None:
            raise ValueError(f"bad criterion: {stripped}")
        criterion_id, kind, evidence = match.group(1), match.group(2), match.group(3).strip()
        if kind not in KINDS:
            raise ValueError(f"bad kind: {kind}")
        if criterion_id in seen:
            raise ValueError(f"duplicate criterion: {criterion_id}")
        seen.add(criterion_id)
        found.append((criterion_id, kind, evidence))
    if not found:
        raise ValueError("no criteria")
    return found


def check(text: str, run) -> tuple[bool, str]:
    """run(node) -> exit code. It is not called for a criterion that already fails."""
    try:
        criteria = parse_criteria(text)
    except ValueError as exc:
        return False, f"FAILED\n{exc}"

    rows: list[tuple[str, str, str, str]] = []
    for criterion_id, kind, evidence in criteria:
        if kind == "human":
            rows.append(_human(criterion_id, evidence))
            continue
        if not evidence or not NODE.match(evidence):
            rows.append((criterion_id, kind, "FAILED", "missing evidence"))
            continue
        if MODEL_RUN.search(evidence):
            rows.append((criterion_id, kind, "FAILED", "model run is not CI evidence"))
            continue
        code = run(evidence)
        if code == 0:
            rows.append((criterion_id, kind, "PASSED", evidence))
        else:
            rows.append((criterion_id, kind, "FAILED", f"pytest exit {code}"))

    ok = all(status == "PASSED" for _, _, status, _ in rows)
    lines = [f"{criterion_id}  {kind}  {status}  {evidence}" for criterion_id, kind, status, evidence in rows]
    lines.append("VERIFIED" if ok else "FAILED")
    return ok, "\n".join(lines)


def _human(criterion_id: str, evidence: str) -> tuple[str, str, str, str]:
    if evidence == "unsigned":
        return (criterion_id, "human", "FAILED", "unsigned")
    if SIGNED.match(evidence):
        return (criterion_id, "human", "PASSED", evidence)
    return (criterion_id, "human", "FAILED", "human criterion needs a signature or the word unsigned")


def run_pytest(node: str) -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", node],
        cwd=ROOT,
        check=False,
    )
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: .venv/bin/python scripts/check_story.py specs/<story>.md", file=sys.stderr)
        return 2
    text = Path(args[0]).read_text(encoding="utf-8")
    ok, report = check(text, run_pytest)
    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
