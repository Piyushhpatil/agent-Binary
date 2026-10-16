"""`taintwalk eval` is listed by the CLI and forwards to eval/pipeline.py (Phase 8, D-032)."""
from __future__ import annotations

import pytest
import shutil
import subprocess
import sys

from taintwalk.config import REPO_ROOT

P6 = REPO_ROOT / "runs" / "p6-gate"
PROGRAMS = REPO_ROOT / "runs" / "p2-extract" / "programs"


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "taintwalk.cli", *args], cwd=REPO_ROOT,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def test_eval_is_listed_and_its_help_comes_from_the_pipeline():
    top = _cli("--help")
    assert top.returncode == 0 and "eval" in top.stdout
    sub = _cli("eval", "--help")
    assert sub.returncode == 0 and "--replay-check" in sub.stdout and "--full" in sub.stdout


@pytest.mark.corpus
def test_eval_runs_the_pipeline(tmp_path):
    progs = tmp_path / "programs"
    progs.mkdir()
    shutil.copy(PROGRAMS / "tw-0015.json", progs / "tw-0015.json")
    proc = _cli("eval", "--local", str(P6), "--programs", str(progs), "--out", str(tmp_path / "o"),
                "--results-md", str(tmp_path / "R.md"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.rstrip().endswith("EVAL OK") and (tmp_path / "R.md").exists()