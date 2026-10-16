"""Phase 10 mini-step 8a (D-042): --mode/--policy wiring and the agent program driver.

The first test is the one that matters most: a fixed-mode command must come out byte-identical to
what Phase 8 and Phase 9 ran, because that command is the input to the replay the gate depends on.
"""
import json
import pathlib

import pytest
from llm_fakes import FakeProvider, ok_response
from corpus_data import corpus_sha

from taintwalk import cli
from taintwalk.analysis.agent import Caps, agent_report, walk_agent_program
from taintwalk.analysis.walk_all import walk_command
from taintwalk.config import load_config

SHA = corpus_sha("tw-0015")  # committed manifest: same value, needs no runs/ data (D-043)

CAPS = Caps(8, 20, 150000, 4000, 12000, 2.0)


def summ():
    return {"params": [], "sources": [], "sinks": [], "propagation": [], "returns_taint": False,
            "callee_effects": [],
            "verdict": {"reason": "r", "mechanism": "none", "region": "not_applicable",
                        "access": "not_applicable", "direction": "not_applicable",
                        "vulnerable": False, "confidence": 0.5}}


def _fn(addr, callees=()):
    return {"addr": addr, "ghidra_name": f"FUN_{addr[2:]}", "in_scope": True,
            "decompile_failed": False, "pseudo_c": "void f(int param_1)\n{\n  return;\n}",
            "callees": [{"kind": "internal", "addr": c, "name": None, "via_thunk": None}
                        for c in callees]}


PROG = {"binary": {"sha256": SHA, "image_base": "0x100000"},
        "functions": [_fn("0x1000", ("0x1100",)), _fn("0x1100"), _fn("0x2000", ("0x1100",))]}


def scripted(n):
    return FakeProvider([ok_response(text=json.dumps(summ())) for _ in range(n)], cache=None)


def test_fixed_mode_command_is_unchanged():
    cmd = walk_command(pathlib.Path("p.json"), pathlib.Path("out"),
                       provider="ollama", offline=True, roots=("0x1a", "0x2b"))
    assert "--mode" not in cmd and "--policy" not in cmd
    assert cmd[cmd.index("--roots") + 1] == "0x1a,0x2b"


def test_agent_mode_adds_mode_and_policy():
    cmd = walk_command(pathlib.Path("p.json"), pathlib.Path("out"),
                       provider="ollama", roots=("0x1a",), mode="agent", policy="scripted")
    assert cmd[cmd.index("--mode") + 1] == "agent"
    assert cmd[cmd.index("--policy") + 1] == "scripted"


def test_agent_run_dir_has_the_walk_shape(tmp_path):
    res = walk_agent_program(scripted(4), PROG, tmp_path, ("0x2000", "0x1000"),
                             policy_name="scripted", caps=CAPS)
    assert res["roots"] == ["0x1000", "0x2000"]          # numeric order, never call order
    summaries = json.loads((tmp_path / "summaries.json").read_text(encoding="utf-8"))
    assert sorted(summaries) == ["0x1000", "0x2000"]
    assert all(v is not None for v in summaries.values())
    assert (tmp_path / "agent.json").is_file()
    assert agent_report(res) == 0


def test_agent_run_dir_is_byte_identical_on_a_repeat(tmp_path):
    out = []
    for name in ("a", "b"):
        d = tmp_path / name
        walk_agent_program(scripted(4), PROG, d, ("0x1000", "0x2000"),
                           policy_name="scripted", caps=CAPS)
        out.append((d / "summaries.json").read_bytes())
    assert out[0] == out[1]


def test_root_not_in_scope_fails_closed(tmp_path):
    with pytest.raises(ValueError):
        walk_agent_program(scripted(1), PROG, tmp_path, ("0x9999",),
                           policy_name="scripted", caps=CAPS)


def test_unknown_policy_fails_closed(tmp_path):
    with pytest.raises(ValueError):
        walk_agent_program(scripted(1), PROG, tmp_path, ("0x1000",),
                           policy_name="guess", caps=CAPS)


def test_cli_agent_mode_requires_roots(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps(PROG), encoding="utf-8")
    assert cli.main(["walk", "--program", str(p), "--mode", "agent",
                     "--run-dir", str(tmp_path / "out")]) == 2
