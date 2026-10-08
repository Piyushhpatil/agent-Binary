"""Phase 10 mini-step 8b (D-042): AGENT log lines, and the per-run metered-token ceiling.

A ceilinged run is void, not a different result: the skipped programs have no summaries, the run
exits non-zero, and the scorer fails closed on a missing root. So the ceiling is a safety stop,
and the fact that thread scheduling decides *which* programs are skipped cannot reach a number.
"""
import json
import pathlib

import pytest

from taintwalk.analysis.agent import RunBudget, program_metered
from taintwalk.analysis.walk_all import SKIPPED_STATUS, parse_log, status_ok, walk_all


def fake_runner(spend):
    """A runner that writes an AGENT OK log and an agent.json spending `spend` metered tokens."""
    def run(cmd, log):
        run_dir = pathlib.Path(cmd[cmd.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "agent.json").write_text(json.dumps({"metered_tokens": spend}),
                                            encoding="utf-8")
        pathlib.Path(log).write_text("roots 2  answered 2\nAGENT OK\n", encoding="utf-8")
        return 0
    return run


def programs(tmp_path, n):
    out = []
    for i in range(n):
        p = tmp_path / f"p{i}.json"
        p.write_text("{}", encoding="utf-8")
        out.append(p)
    return out


def test_agent_verdict_lines_are_recognised():
    """parse_log returns the whole verdict line, tail included; status_ok is the prefix test."""
    assert parse_log("AGENT OK\n")["status"] == "AGENT OK"
    assert parse_log("AGENT FAIL\n")["status"] == "AGENT FAIL"
    assert parse_log("roots 2  answered 2\nAGENT OK\n")["status"] == "AGENT OK"
    assert parse_log("WALK OK  13 walked, 37 skipped\n")["status"] == "WALK OK  13 walked, 37 skipped"
    assert parse_log("nothing here\n")["status"] == "no WALK line"


def test_status_ok_matches_a_real_line_with_its_tail():
    # the regression this guards: a fixed walk's real line must still count as ok
    assert status_ok("WALK OK  13 walked, 37 skipped")
    assert status_ok("WALK OK") and status_ok("AGENT OK")
    assert not status_ok("WALK FAIL  2 context overflows")
    assert not status_ok("AGENT FAIL") and not status_ok("no WALK line")
    assert not status_ok(SKIPPED_STATUS)


def test_without_a_budget_every_program_runs(tmp_path):
    res = walk_all(programs(tmp_path, 4), tmp_path / "out", jobs=1, runner=fake_runner(100),
                   progress=lambda s: None, mode="agent", policy="scripted")
    assert len(res) == 4 and all(r.ok for r in res)


def test_ceiling_skips_the_rest_and_overshoots_by_at_most_one(tmp_path):
    b = RunBudget(250)
    res = walk_all(programs(tmp_path, 4), tmp_path / "out", jobs=1, runner=fake_runner(100),
                   progress=lambda s: None, budget=b, mode="agent", policy="scripted")
    ran = [r for r in res if r.status != SKIPPED_STATUS]
    skipped = [r for r in res if r.status == SKIPPED_STATUS]
    assert len(ran) == 3 and len(skipped) == 1          # claimed at 0, 100, 200; refused at 300
    assert b.spent == 300 and b.skipped == ["p3"]
    assert not any(r.ok for r in skipped) and all(r.rc == 2 for r in skipped)


def test_a_fixed_run_is_never_charged(tmp_path):
    def run(cmd, log):
        pathlib.Path(log).write_text("WALK OK\n", encoding="utf-8")
        return 0
    b = RunBudget(10)
    res = walk_all(programs(tmp_path, 2), tmp_path / "out", jobs=1, runner=run,
                   progress=lambda s: None, budget=b)
    assert b.spent == 0 and all(r.ok for r in res)      # no agent.json: nothing to charge


def test_program_metered_and_budget_guards(tmp_path):
    assert program_metered(tmp_path) == 0
    (tmp_path / "agent.json").write_text(json.dumps({"metered_tokens": 42}), encoding="utf-8")
    assert program_metered(tmp_path) == 42
    with pytest.raises(ValueError):
        RunBudget(0)
