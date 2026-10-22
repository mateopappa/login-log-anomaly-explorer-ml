"""Structural guard: detection and investigation code must never import ground truth.

This is a static AST scan. It catches direct imports (absolute and relative) of
``login_anomaly.simulation.ground_truth``. It is a structural guard, not an
absolute guarantee. It does not see dynamic imports (``importlib``,
``__import__``), attribute access through a parent package (for example
``import login_anomaly.simulation as s; s.ground_truth``), or code outside
``src/login_anomaly``. Code review remains necessary.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

import login_anomaly

PACKAGE_ROOT = Path(login_anomaly.__file__).parent
FORBIDDEN = "login_anomaly.simulation.ground_truth"
# The generator module also carries the ground-truth API. Its evaluation-only
# entry point and its truth-bearing type must stay out of detection and investigation code.
FORBIDDEN_NAMES = frozenset(
    f"login_anomaly.simulation.generator.{name}" for name in ("generate_with_truth", "GeneratedDataset")
)
# Only these subpackages may import ground truth. "evaluation" is reserved for
# later blocks and does not exist yet.
ALLOWED_SUBPACKAGES = frozenset({"simulation", "evaluation"})


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    imported: str


def _module_name(package_root: Path, path: Path) -> str:
    parts = list(path.relative_to(package_root.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_from(node: ast.ImportFrom, package: str) -> str:
    if node.level == 0:
        return node.module or ""
    base = package.split(".")
    if node.level > 1:
        base = base[: len(base) - (node.level - 1)]
    prefix = ".".join(base)
    return f"{prefix}.{node.module}" if node.module else prefix


def _imported_names(tree: ast.AST, package: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from(node, package)
            found.append((node.lineno, base))
            found.extend((node.lineno, f"{base}.{alias.name}") for alias in node.names)
    return found


def scan_package(package_root: Path) -> list[Violation]:
    violations: list[Violation] = []
    for path in sorted(package_root.rglob("*.py")):
        rel = path.relative_to(package_root)
        if rel.parts and rel.parts[0] in ALLOWED_SUBPACKAGES:
            continue
        module = _module_name(package_root, path)
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        reported_lines: set[int] = set()
        for lineno, name in _imported_names(tree, package):
            is_forbidden = (
                name == FORBIDDEN or name.startswith(FORBIDDEN + ".") or name in FORBIDDEN_NAMES
            )
            # One statement such as `from x import y` yields several candidate
            # names; report it once.
            if is_forbidden and lineno not in reported_lines:
                reported_lines.add(lineno)
                violations.append(Violation(str(rel), lineno, name))
    return violations


def test_no_module_outside_simulation_imports_ground_truth() -> None:
    violations = scan_package(PACKAGE_ROOT)
    assert violations == [], f"ground truth imported outside simulation: {violations}"


def _write_package(tmp_path: Path, relative: str, source: str) -> Path:
    package_root = tmp_path / "login_anomaly"
    target = package_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return package_root


@pytest.mark.parametrize(
    "source",
    [
        "from login_anomaly.simulation.ground_truth import ScenarioLabel\n",
        "import login_anomaly.simulation.ground_truth\n",
        "from login_anomaly.simulation import ground_truth\n",
        "from ..simulation.ground_truth import ScenarioLabel\n",
    ],
    ids=["from-absolute", "import-absolute", "from-package-name", "from-relative"],
)
def test_scanner_detects_forbidden_import_forms(tmp_path: Path, source: str) -> None:
    # Control case: proves the scanner catches each prohibited import form.
    package_root = _write_package(tmp_path, "detectors/rules.py", source)
    violations = scan_package(package_root)
    assert len(violations) == 1
    assert violations[0].file == "detectors/rules.py"
    assert violations[0].imported.startswith(FORBIDDEN)


@pytest.mark.parametrize(
    "source",
    [
        "from login_anomaly.simulation.generator import generate_with_truth\n",
        "from login_anomaly.simulation.generator import GeneratedDataset\n",
    ],
    ids=["truth-function", "truth-type"],
)
def test_scanner_detects_truth_api_of_generator(tmp_path: Path, source: str) -> None:
    package_root = _write_package(tmp_path, "detectors/rules.py", source)
    violations = scan_package(package_root)
    assert len(violations) == 1
    assert violations[0].imported.startswith("login_anomaly.simulation.generator.")


def test_scanner_allows_generate_and_module_import(tmp_path: Path) -> None:
    # Control: the public event-only API and the module itself are not the forbidden names.
    package_root = _write_package(
        tmp_path,
        "detectors/rules.py",
        "from login_anomaly.simulation.generator import generate\n"
        "from login_anomaly.simulation import generator\n",
    )
    assert scan_package(package_root) == []


def test_scanner_ignores_forbidden_import_inside_simulation(tmp_path: Path) -> None:
    package_root = _write_package(
        tmp_path,
        "simulation/generator.py",
        "from login_anomaly.simulation.ground_truth import ScenarioLabel\n",
    )
    assert scan_package(package_root) == []


def test_scanner_ignores_allowed_imports(tmp_path: Path) -> None:
    package_root = _write_package(
        tmp_path,
        "detectors/rules.py",
        "from login_anomaly.events import AuthEvent\n",
    )
    assert scan_package(package_root) == []


RUNTIME_MODULES = (
    "workflow.py",
    "correlation.py",
    "agentic/cases.py",
    "agentic/provider.py",
    "agentic/case_investigator.py",
    "agentic/reviewer.py",
    "agentic/investigator.py",
    "agentic/tools.py",
    "agentic/contracts.py",
    "threat_lab/proposals.py",
    "dashboard/view.py",
    "live/sources.py",
    "live/engine.py",
)


@pytest.mark.parametrize("module", RUNTIME_MODULES)
def test_runtime_modules_cannot_reach_labels_through_evaluation(module: str) -> None:
    # Runtime agents and workflow stages run before labels exist; the evaluation layer holds them.
    tree = ast.parse((PACKAGE_ROOT / module).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert not any(name.startswith(("login_anomaly.evaluation", FORBIDDEN)) for name in imported), imported
