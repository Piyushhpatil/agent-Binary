"""`taintwalk walk --all` (Phase 8, D-032): program lists, the per-program command, log parsing,
result order under parallel jobs, the summary file, and a real offline batch that must
reproduce Phase 7 shakedown walks byte for byte."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from taintwalk.analysis.walk_all import (
    parse_log,
    read_program_list,
    run_walk_all,
    walk_all,
    walk_command,
)
from taintwalk.config import REPO_ROOT

SHAKEDOWN = REPO_ROOT / "runs" / "p7-walk"
OK_LOG = (
    "provider: ollama  model ornith:9b  cache on  run dir x\n"
    "walked             : 3  skipped isolated 5  components 3 (recursive 0)\n"
    "tokens (this run)  : in 1200  out 300  model time 9.5 s  cache hits 1 of 3 calls\n"
    "WALK OK"
)


def _progs(tmp_path: Path, names: list[str]) -> list[Path]:
    d = tmp_path / "programs"
    d.mkdir(exist_ok=True)
    out = []
    for n in names:
        p = d / f"{n}.json"
        p.write_text("{}", encoding="utf-8")
        out.append(p)
    return out


def _fake_runner(fail: set[str], delays: dict[str, float] | None = None):
    """Stands in for the subprocess: writes a walk log and returns an exit code."""
    def run(cmd: list[str], log: Path) -> int:
        name = Path(cmd[cmd.index("--program") + 1]).stem
        time.sleep((delays or {}).get(name, 0.0))
        log.write_text("WALK FAIL" if name in fail else OK_LOG, encoding="utf-8")
        return 1 if name in fail else 0
    return run


# ---- program lists --------------------------------------------------------------------

def test_program_list_from_a_text_file_and_from_a_directory(tmp_path):
    a, b = _progs(tmp_path, ["tw-0002", "tw-0001"])
    lst = tmp_path / "programs.txt"
    lst.write_text(f"# comment\n{a}\n\n{b}\n", encoding="utf-8")
    assert read_program_list(lst) == [a, b]                    # a list keeps its order
    assert read_program_list(tmp_path / "programs") == [b, a]  # a directory is sorted by name


def test_relative_paths_in_a_list_resolve_from_the_repo_root(tmp_path):
    lst = tmp_path / "programs.txt"
    lst.write_text("pyproject.toml\n", encoding="utf-8")  # any file that exists at the repo root
    assert read_program_list(lst) == [REPO_ROOT / "pyproject.toml"]


@pytest.mark.parametrize("content,match", [("# only a comment\n", "no programs"),
                                           ("/nonexistent/tw-9999.json\n", "missing")])
def test_bad_lists_fail_before_anything_runs(tmp_path, content, match):
    lst = tmp_path / "programs.txt"
    lst.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        read_program_list(lst)


def test_two_programs_that_would_share_a_run_dir_are_rejected(tmp_path):
    (p,) = _progs(tmp_path, ["tw-0001"])
    (tmp_path / "other").mkdir()
    q = tmp_path / "other" / "tw-0001.json"
    q.write_text("{}", encoding="utf-8")
    lst = tmp_path / "programs.txt"
    lst.write_text(f"{p}\n{q}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="share a run dir"):
        read_program_list(lst)


# ---- the command and the log ------------------------------------------------------------

def test_the_command_is_the_single_program_walk_with_flags_passed_through(tmp_path):
    cmd = walk_command(Path("/p/tw-0001.json"), tmp_path / "tw-0001", provider="ollama",
                       with_baseline=True, offline=True)
    assert cmd == [sys.executable, "-m", "taintwalk.cli", "walk",
                   "--program", "/p/tw-0001.json", "--run-dir", str(tmp_path / "tw-0001"),
                   "--provider", "ollama", "--with-baseline", "--offline"]
    bare = walk_command(Path("/p/x.json"), tmp_path / "x")
    assert not {"--provider", "--no-cache", "--retry-failed", "--offline"} & set(bare)


def test_parse_log_reads_the_verdict_and_token_lines():
    assert parse_log(OK_LOG) == {"status": "WALK OK", "tokens_in": 1200, "tokens_out": 300,
                                 "model_s": 9.5, "cache_hits": 1, "calls": 3}
    early = parse_log("provider: x\nWALK FAIL: OfflineMiss: ollama/ornith:9b: no cached reply for key ab\n")
    assert early["status"].startswith("WALK FAIL: OfflineMiss") and early["tokens_in"] is None
    assert parse_log("Traceback (most recent call last):\n")["status"] == "no WALK line"


# ---- the batch ------------------------------------------------------------------------

def test_results_come_back_in_input_order_under_parallel_jobs(tmp_path):
    progs = _progs(tmp_path, ["tw-0001", "tw-0002", "tw-0003"])
    seen: list[str] = []
    res = walk_all(progs, tmp_path / "root", jobs=3, progress=seen.append,
                   runner=_fake_runner(set(), delays={"tw-0001": 0.3}))  # the first finishes last
    assert [r.name for r in res] == ["tw-0001", "tw-0002", "tw-0003"]
    assert seen[-1].startswith("[3/3] tw-0001")
    assert all(r.ok and r.tokens_in == 1200 for r in res)
    assert (tmp_path / "root" / "logs" / "tw-0002.log").read_text(encoding="utf-8") == OK_LOG


def test_a_failed_program_does_not_stop_the_batch_but_fails_its_exit_code(tmp_path, capsys):
    progs = _progs(tmp_path, ["tw-0001", "tw-0002"])
    lst = tmp_path / "programs.txt"
    lst.write_text("\n".join(str(p) for p in progs), encoding="utf-8")
    rc = run_walk_all(lst, tmp_path / "root", runner=_fake_runner({"tw-0001"}), provider="ollama")
    out = capsys.readouterr().out
    assert rc == 1 and "NOT OK tw-0001" in out and out.rstrip().endswith("WALK ALL FAIL: 1/2 WALK OK")
    doc = json.loads((tmp_path / "root" / "walk_all.json").read_text(encoding="utf-8"))
    assert doc["programs"] == 2 and doc["walk_ok"] == 1 and doc["flags"] == {"provider": "ollama"}
    assert [r["name"] for r in doc["results"]] == ["tw-0001", "tw-0002"]
    assert doc["tokens_in"] == 1200 and doc["calls"] == 3
    assert run_walk_all(lst, tmp_path / "r2", jobs=0) == 2
    assert run_walk_all(tmp_path / "absent.txt", tmp_path / "r3") == 1


# ---- a real offline batch ----------------------------------------------------------------

def test_offline_batch_reproduces_shakedown_walks_byte_for_byte(tmp_path):
    """Corpus-dependent: fails, never skips, without runs/p7-walk. --offline means this replay
    cannot reach a model, and byte-identical summaries.json shows the batch path adds nothing."""
    lines = (SHAKEDOWN / "programs.txt").read_text(encoding="utf-8").split()[:2]
    lst = tmp_path / "programs.txt"
    lst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    root = tmp_path / "root"
    proc = subprocess.run(
        [sys.executable, "-m", "taintwalk.cli", "walk", "--all", "--programs", str(lst),
         "--run-dir", str(root), "--provider", "ollama", "--offline"],
        cwd=REPO_ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WALK ALL OK: 2/2" in proc.stdout
    for line in lines:
        name = Path(line).stem
        assert (root / name / "summaries.json").read_bytes() == \
            (SHAKEDOWN / name / "summaries.json").read_bytes()
    doc = json.loads((root / "walk_all.json").read_text(encoding="utf-8"))
    assert doc["walk_ok"] == 2 and doc["tokens_in"] == 0 and doc["tokens_out"] == 0