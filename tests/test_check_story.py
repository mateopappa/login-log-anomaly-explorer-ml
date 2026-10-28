"""The story closer fails closed. A green run of the real story is not this test."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORY = ROOT / "specs" / "agent-investigation.md"


def _checker():
    spec = importlib.util.spec_from_file_location("check_story", ROOT / "scripts" / "check_story.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_evidence_is_red_and_does_not_run_pytest() -> None:
    checker = _checker()
    calls: list[str] = []
    ok, report = checker.check(
        "# s\n\n## Criteria\n\n- AC-1 | script |\n",
        lambda node: calls.append(node) or 0,
    )
    assert not ok
    assert calls == []
    assert "AC-1  script  FAILED  missing evidence" in report
    assert report.endswith("FAILED")


def test_unsigned_human_is_red() -> None:
    checker = _checker()
    ok, report = checker.check(
        "# s\n\n## Criteria\n\n- AC-H | human | unsigned\n",
        lambda node: 0,
    )
    assert not ok
    assert "unsigned" in report
    assert report.endswith("FAILED")


def test_model_run_is_not_ci_evidence() -> None:
    checker = _checker()
    calls: list[str] = []
    ok, report = checker.check(
        "# s\n\n## Criteria\n\n- AC-M | script | tests/test_haiku_provider.py::test_haiku_requires_api_key\n",
        lambda node: calls.append(node) or 0,
    )
    assert not ok
    assert calls == []
    assert "model run is not CI evidence" in report


def test_green_node_verifies_and_red_node_does_not() -> None:
    checker = _checker()
    story = (
        "# s\n\n## Criteria\n\n"
        "- AC-1 | fixture | tests/test_agentic_tools.py::test_registry_matches_the_documented_read_only_tools\n"
    )
    ok, report = checker.check(story, lambda node: 0)
    assert ok
    assert report.endswith("VERIFIED")

    ok, report = checker.check(story, lambda node: 1)
    assert not ok
    assert "pytest exit 1" in report
    assert report.endswith("FAILED")


def test_cli_exits_red_when_evidence_is_missing(tmp_path: Path) -> None:
    checker = _checker()
    story = tmp_path / "story.md"
    story.write_text("# s\n\n## Criteria\n\n- AC-1 | judge |\n", encoding="utf-8")
    assert checker.main([str(story)]) == 1


def test_shipped_story_names_tests_that_exist() -> None:
    checker = _checker()
    criteria = checker.parse_criteria(STORY.read_text(encoding="utf-8"))
    assert criteria
    for criterion_id, kind, evidence in criteria:
        assert kind in {"script", "fixture", "judge"}, criterion_id
        path, _, test_name = evidence.partition("::")
        file = ROOT / path
        assert file.is_file(), evidence
        if test_name:
            assert f"def {test_name}(" in file.read_text(encoding="utf-8")
