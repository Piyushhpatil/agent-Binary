"""I1 by construction: the analysis side must not reach ground truth.

Static (AST + string constants). It stops accidents, not deliberate evasion; the
runtime leak gate is the second layer. `util.leakcheck` is the ONLY sanctioned path,
and only through its public names.
"""
from __future__ import annotations

import ast
from pathlib import Path

from taintwalk.config import REPO_ROOT

GUARDED = [REPO_ROOT / "src/taintwalk/analysis", REPO_ROOT / "src/taintwalk/llm"]
FORBIDDEN_MODULES = ("taintwalk.eval", "taintwalk.corpus", "taintwalk.extract.report")
FORBIDDEN_RELATIVE = ("eval", "corpus", "extract.report")
FORBIDDEN_STRINGS = ("manifest.json", "labels.json", "label_report", "extract_report",
                     *FORBIDDEN_MODULES)


def _is_forbidden(mod: str) -> bool:
    return any(mod == f or mod.startswith(f + ".") for f in FORBIDDEN_MODULES)


def violations(dirs: list[Path]) -> tuple[int, list[str]]:
    files = [p for d in dirs for p in sorted(d.rglob("*.py"))]
    out: list[str] = []
    for py in files:
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            where = f"{py.name}:{getattr(node, 'lineno', '?')}"
            if isinstance(node, ast.Import):
                out += [f"{where} import {a.name}" for a in node.names if _is_forbidden(a.name)]
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level == 0:
                    full = [mod] + [f"{mod}.{a.name}" for a in node.names]
                    if any(_is_forbidden(m) for m in full):
                        out.append(f"{where} from {mod} import ...")
                elif any(mod == f or mod.startswith(f + ".") for f in FORBIDDEN_RELATIVE):
                    out.append(f"{where} relative import {'.' * node.level}{mod}")
                if mod.endswith("leakcheck"):
                    out += [f"{where} private leakcheck name {a.name}"
                            for a in node.names if a.name.startswith("_")]
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                out += [f"{where} string mentions {s!r}"
                        for s in FORBIDDEN_STRINGS if s in node.value]
    return len(files), out


def test_analysis_and_llm_cannot_reach_ground_truth():
    n, v = violations(GUARDED)
    assert n >= 2, "scanned too few files; the check would pass vacuously"
    assert v == [], "\n".join(v)


def test_planted_violations_are_caught(tmp_path):
    pkg = tmp_path / "analysis"
    pkg.mkdir()
    (pkg / "planted.py").write_text(
        "from taintwalk.eval.join import run_label\n"
        "from ..corpus import groundtruth\n"
        "from taintwalk.util.leakcheck import _name_rx\n"
        "import taintwalk.extract.report\n"
        "P = 'corpus/manifest.json'\n",
        encoding="utf-8",
    )
    _, v = violations([pkg])
    assert len(v) >= 5, v