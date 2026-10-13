"""Agent mode prints the fixed walk's `tokens (this run)` line from usage.json (mini-step 10e).

Before this, walk --all recorded 0 tokens for every agent program, because the line it parses was
never printed. The line is stdout only, so it cannot change summaries.json or agent.json."""
import json

from taintwalk.analysis.agent import agent_report, usage_line
from taintwalk.analysis.walk_all import TOKENS_LINE, parse_log


def _usage(tmp_path, records):
    (tmp_path / "usage.json").write_text(json.dumps(
        {"written_at": "x", "providers": [{"records": records}]}), encoding="utf-8")


def _rec(hit, tin, tout, wall):
    return {"cache_hit": hit, "wall_s": wall,
            "usage": {"input_tokens": tin, "output_tokens": tout,
                      "thinking_tokens": 0, "provider_cached_input_tokens": 0}}


RESULT = {"functions": {"0x10": {"judge": "ok", "stop": "finish"}}, "roots": ["0x10"],
          "policy": "llm", "calls": 3, "metered_tokens": 100, "context_overflows": 0}


def test_usage_line_counts_live_calls_only(tmp_path):
    _usage(tmp_path, [_rec(False, 100, 20, 1.5), _rec(False, 50, 5, 0.5), _rec(True, 0, 0, 0.01)])
    line = usage_line(tmp_path)
    assert line == ("tokens (this run)  : in 150  out 25  model time 2.0 s  "
                    "cache hits 1 of 3 calls")
    m = TOKENS_LINE.search(line)
    assert m and m.groups() == ("150", "25", "2.0", "1", "3")


def test_no_usage_file_prints_nothing(tmp_path, capsys):
    assert usage_line(tmp_path) is None
    assert agent_report(RESULT, tmp_path) == 0
    assert "tokens (this run)" not in capsys.readouterr().out


def test_agent_report_line_is_what_walk_all_parses(tmp_path, capsys):
    _usage(tmp_path, [_rec(False, 7, 3, 0.25)])
    assert agent_report(RESULT, tmp_path) == 0
    log = capsys.readouterr().out
    p = parse_log(log)
    assert p["status"] == "AGENT OK"
    assert (p["tokens_in"], p["tokens_out"]) == (7, 3)


def test_without_run_dir_the_report_is_unchanged(capsys):
    assert agent_report(RESULT) == 0
    out = capsys.readouterr().out
    assert "tokens (this run)" not in out and out.rstrip().endswith("AGENT OK")