"""`taintwalk eval` wiring (Phase 8, D-032, D-034), on the Phase 6 gate walk (tw-0015, a disclosed development
binary): every section renders, the output is deterministic, the full gate refuses partial rungs, and the
command-line entry replays offline and loads no provider module. Corpus-dependent: fails, never skips."""
from __future__ import annotations

import pytest
import json
import shutil
import subprocess
import sys

from taintwalk.config import REPO_ROOT
from taintwalk.eval.pipeline import run_eval

P6 = REPO_ROOT / "runs" / "p6-gate"
LABELS = REPO_ROOT / "runs" / "p2-extract" / "labels"
PROGRAMS = REPO_ROOT / "runs" / "p2-extract" / "programs"
REQUIRED = ("## Main table", "## By stratum", "## Secondary rule", "## Typed ladder", "## Confidence",
            "## Pre-registered tests", "## Ablation", "## Provider comparison", "## By CWE class",
            "## By flow variant", "## Cost and runtime", "## Error analysis", "### Few-shot parroting",
            "### Sanitizer-literal shortcut", "### Abstentions", "### Hand-coded analysis",
            "## Development-set disclosure", "## Future work", "## Limitations")


def _progs(tmp_path):
    d = tmp_path / "programs"
    d.mkdir()
    shutil.copy(PROGRAMS / "tw-0015.json", d / "tw-0015.json")
    return d


def _kw(tmp_path, **over):
    kw = {"local_root": P6, "cloud_root": None, "programs_dir": _progs(tmp_path), "labels_dir": LABELS,
          "out_dir": tmp_path / "o", "results_md": tmp_path / "RESULTS.md", "status": "TEST",
          "error_analysis": tmp_path / "absent.md"}
    kw.update(over)
    return kw


@pytest.mark.corpus
def test_every_section_renders_and_a_rerun_is_byte_identical(tmp_path):
    kw = _kw(tmp_path)
    rc, ev = run_eval(**kw)
    assert rc == 0
    text = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
    for h in REQUIRED:
        assert h in text, h
    assert "Deferred pending API funding (D-034)" in text
    assert sorted(p.stem for p in (tmp_path / "o" / "scores").glob("*.json")) == ["R1", "R2", "R3", "R4", "R5"]
    assert ev["cloud_deferred"] is True and ev["tests"]["family_name"].startswith("D-034")
    assert ev["tests"]["family"] == 6 and ev["tests"]["holm_applied"] and ev["tests"]["missing"] == []
    assert set(ev["ablation"]) == {"local"} and sum(ev["ablation"]["local"]["counts"].values()) == 2
    assert set(ev["errors"]) == {"R4", "R5"} and ev["error_sample"]["rung"] == "R5"
    assert (tmp_path / "o" / "errors" / "worksheet-R5.md").exists()
    first_md = (tmp_path / "RESULTS.md").read_bytes()
    first_ev = (tmp_path / "o" / "eval.json").read_bytes()
    rc2, _ = run_eval(**kw)
    assert rc2 == 0
    assert (tmp_path / "RESULTS.md").read_bytes() == first_md
    assert (tmp_path / "o" / "eval.json").read_bytes() == first_ev


@pytest.mark.corpus
def test_the_local_only_gate_requires_r1_to_r5_on_636_roots(tmp_path):
    rc, ev = run_eval(**_kw(tmp_path, full=True))
    assert rc == 1
    assert "R5: 2 roots, expected 636" in ev["problems"]
    assert not any("R6" in p or "R7" in p for p in ev["problems"])


@pytest.mark.corpus
def test_cli_replays_offline_and_loads_no_provider_module(tmp_path):
    progs = _progs(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "taintwalk.eval.pipeline", "--local", str(P6), "--programs", str(progs),
         "--out", str(tmp_path / "o"), "--results-md", str(tmp_path / "R.md"), "--replay-check", "--jobs", "1"],
        cwd=REPO_ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "provider modules loaded: none" in proc.stdout and proc.stdout.rstrip().endswith("EVAL OK")
    ev = json.loads((tmp_path / "o" / "eval.json").read_text(encoding="utf-8"))
    assert ev["replay"]["local"]["identical"] == ev["replay"]["local"]["programs"] == 1