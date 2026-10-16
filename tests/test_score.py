"""`taintwalk score` (Phase 7): deterministic, provider-free, fails closed. It scores a copy of the
Phase 6 gate run in a temp dir, so the test never writes into runs/. The CLI runs in a subprocess
because this pytest process has already imported taintwalk.llm through other tests."""
from __future__ import annotations

import pytest
import shutil
import subprocess
import sys

from taintwalk.config import REPO_ROOT
from taintwalk.eval.score import discover_runs

GATE = REPO_ROOT / "runs/p6-gate"


def _score(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "taintwalk.cli", "score", *map(str, args)],
                          capture_output=True, text=True, cwd=REPO_ROOT, timeout=300)


@pytest.mark.corpus
def test_score_cli_is_deterministic_and_loads_no_provider(tmp_path):
    run = tmp_path / "gate"
    run.mkdir()
    for name in ("walk.json", "summaries.json"):
        shutil.copy(GATE / name, run / name)
    md = tmp_path / "RESULTS.test.md"
    first = _score(run, "--report", "--results-md", md)
    assert first.returncode == 0, first.stdout + first.stderr
    score1, md1 = (run / "eval" / "score.json").read_bytes(), md.read_bytes()
    second = _score(run, "--report", "--results-md", md)
    assert second.returncode == 0, second.stdout + second.stderr
    assert (run / "eval" / "score.json").read_bytes() == score1
    assert md.read_bytes() == md1
    out = first.stdout
    for heading in ("PRIMARY", "SECONDARY", "TYPED LADDER", "RIGHT BUG, WRONG CWE", "BY CLASS",
                    "BY FLOW", "CONFIDENCE", "RELIABILITY BINS", "DIAGNOSTICS"):
        assert heading in out, heading
    assert "provider modules loaded: none" in out
    assert "roots not walked   : 0" in out
    assert out.rstrip().endswith("SCORE OK")
    assert (run / "findings.json").exists()
    assert "DEVELOPMENT OBSERVATION" in md.read_text(encoding="utf-8")


def test_score_cli_fails_closed_without_walk_runs(tmp_path):
    r = _score(tmp_path)
    assert r.returncode == 1
    assert "SCORE FAIL" in r.stdout


def test_discover_runs(tmp_path):
    for name in ("tw-0002", "tw-0001"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "walk.json").write_text("{}", encoding="utf-8")
    (tmp_path / "eval").mkdir()
    (tmp_path / "logs").mkdir()
    assert discover_runs(tmp_path) == [tmp_path / "tw-0001", tmp_path / "tw-0002"]
    assert discover_runs(tmp_path / "tw-0001") == [tmp_path / "tw-0001"]