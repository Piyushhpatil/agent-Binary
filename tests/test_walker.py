"""Bottom-up walk with a scripted provider (Phase 6, D-026)."""
from __future__ import annotations

import json

import pytest

from llm_fakes import FakeProvider, ok_response
from taintwalk.analysis.prompts import CALLEE_HEADER, build_prompt
from taintwalk.analysis.walker import walk_program, walk_report
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.util.leakcheck import LeakError

# A real corpus sha, so the name layer of the gate runs; the program contents are synthetic.
SHA = json.loads((REPO_ROOT / load_config()["extract"]["out_dir"] / "programs" / "tw-0015.json")
                 .read_text(encoding="utf-8"))["binary"]["sha256"]
BASE = 0x100000


def scripted(responses: list) -> FakeProvider:
    """A scripted provider with no cache: every complete() consumes one response."""
    return FakeProvider(responses, cache=None)


def name(addr: str) -> str:
    return f"FUN_{int(addr, 16) + BASE:08x}"


def fn(addr: str, callees=(), *, in_scope: bool = True) -> dict:
    calls = "".join(f"  {name(c)}(param_1);\n" for c in callees)
    return {
        "addr": addr, "ghidra_name": name(addr), "in_scope": in_scope, "decompile_failed": False,
        "pseudo_c": f"void {name(addr)}(char *param_1)\n{{\n{calls}  return;\n}}\n" if in_scope else None,
        "callees": [{"kind": "internal", "addr": c} for c in callees],
    }


def prog(fns: list[dict]) -> dict:
    return {"binary": {"sha256": SHA, "image_base": hex(BASE)}, "functions": fns}


def summ(*, vulnerable: bool = False, guard: str = "") -> dict:
    where = ("stack", "write", "past_end") if vulnerable else ("not_applicable",) * 3
    return {
        "params": [{"index": 0, "inferred_type": "char *", "role": "buffer"}],
        "sources": [],
        "sinks": [{"sink_kind": "call_arg", "callee": "strcpy", "evidence_line": 1, "tainted_args": [0],
                   "guarded": bool(guard), "guard_expr": guard, "confidence": 0.5}],
        "propagation": [{"src": "param:0", "dst": "sink:0", "sanitized": bool(guard)}],
        "returns_taint": False,
        "callee_effects": [],
        "verdict": {"reason": "r", "mechanism": "out_of_bounds_access" if vulnerable else "none",
                    "region": where[0], "access": where[1], "direction": where[2],
                    "vulnerable": vulnerable, "confidence": 0.5},
    }


def resp(**kw):
    return ok_response(text=json.dumps(summ(**kw)))


def walk(p, fake, run_dir, **kw):
    kw.setdefault("max_chars", 12000)
    kw.setdefault("max_iterations", 3)
    return walk_program(fake, p, run_dir, log=lambda s: None, **kw)


def chain():
    return prog([fn("0x1100", ["0x1200"]), fn("0x1200", ["0x1300"]), fn("0x1300"), fn("0x1400")])


def test_chain_walks_callees_first_and_injects_their_summaries(tmp_path):
    p = chain()
    fake = scripted([resp(vulnerable=True), resp(), resp()])
    res = walk(p, fake, tmp_path)
    users = [c["user"] for c in fake.calls]
    assert [u.split(".", 1)[0] for u in users] == [
        "Function FUN_00101300", "Function FUN_00101200", "Function FUN_00101100"]
    leaf = p["functions"][2]
    assert users[0] == build_prompt(leaf["ghidra_name"], leaf["pseudo_c"], binary_sha256=SHA).user
    assert CALLEE_HEADER in users[1]
    assert "FUN_00101300, called on line 3\n" in users[1]
    assert "verdict: vulnerable, out_of_bounds_access stack/write/past_end" in users[1]
    assert "FUN_00101200, called on line 3\n" in users[2] and "verdict: not vulnerable" in users[2]
    assert res["plan"].skipped_isolated == ("0x1400",)
    summaries = json.loads((tmp_path / "summaries.json").read_text(encoding="utf-8"))
    assert sorted(summaries) == ["0x1100", "0x1200", "0x1300"] and all(summaries.values())
    assert json.loads((tmp_path / "walk.json").read_text(encoding="utf-8"))["skipped_isolated"] == ["0x1400"]
    assert walk_report(res) == 0


def test_failed_callee_becomes_a_stub_and_its_caller_still_runs(tmp_path):
    p = prog([fn("0x1100", ["0x1300"]), fn("0x1300")])
    fake = scripted([ok_response(text="not json"), ok_response(text="still not json"), resp()])
    res = walk(p, fake, tmp_path)
    assert res["rows"]["0x1300"]["status"] != "ok"
    assert len(fake.calls) == 3
    assert "FUN_00101300, called on line 3: no summary (analysis failed:" in fake.calls[-1]["user"]
    assert json.loads((tmp_path / "summaries.json").read_text(encoding="utf-8"))["0x1300"] is None
    assert walk_report(res) == 0


def test_a_leak_in_callee_output_aborts_before_the_caller_is_sent(tmp_path):
    p = prog([fn("0x1100", ["0x1300"]), fn("0x1300")])
    fake = scripted([resp(guard="CWE-121 x")])
    with pytest.raises(LeakError):
        walk(p, fake, tmp_path)
    assert len(fake.calls) == 1


def test_recursive_component_converges_and_keeps_every_iteration(tmp_path):
    p = prog([fn("0x1000", ["0x1100"]), fn("0x1100", ["0x1200"]), fn("0x1200", ["0x1100"])])
    fake = scripted([resp() for _ in range(5)])
    res = walk(p, fake, tmp_path)
    assert [c for c in res["components"] if c["recursive"]] == [
        {"members": ["0x1100", "0x1200"], "recursive": True, "iterations": 2, "converged": True}]
    users = [c["user"] for c in fake.calls]
    assert all("not yet available (recursive call)" in u for u in users[:2])
    assert not any("not yet available" in u for u in users[2:])
    assert users[4].startswith("Function FUN_00101000.")
    for it in (0, 1):
        assert (tmp_path / "summaries" / f"{SHA[:12]}_0x1100.it{it}.json").exists()
    assert walk_report(res) == 0


def test_oscillating_component_hits_the_cap_and_terminates(tmp_path):
    p = prog([fn("0x1100", ["0x1200"]), fn("0x1200", ["0x1100"])])
    fake = scripted([resp(guard=f"n < {k}") for k in (1, 1, 2, 2, 3, 3)])
    res = walk(p, fake, tmp_path)
    assert res["components"] == [
        {"members": ["0x1100", "0x1200"], "recursive": True, "iterations": 3, "converged": False}]
    assert len(fake.calls) == 6
    assert walk_report(res) == 0


def test_walk_output_is_deterministic(tmp_path):
    def once(d):
        walk(chain(), scripted([resp(vulnerable=True), resp(), resp()]), d)
        return (d / "summaries.json").read_bytes()
    assert once(tmp_path / "a") == once(tmp_path / "b")


def test_baseline_reruns_callers_without_context(tmp_path):
    p = prog([fn("0x1100", ["0x1300"]), fn("0x1300")])
    fake = scripted([resp(vulnerable=True), resp(vulnerable=True), resp()])
    res = walk(p, fake, tmp_path, with_baseline=True)
    assert sorted(res["baseline"]) == ["0x1100"]
    caller = p["functions"][0]
    assert fake.calls[2]["user"] == build_prompt(caller["ghidra_name"], caller["pseudo_c"], binary_sha256=SHA).user
    assert (tmp_path / "baseline" / "summaries" / f"{SHA[:12]}_0x1100.json").exists()
    assert walk_report(res) == 0


def test_out_of_scope_callee_renders_a_stub(tmp_path):
    p = prog([fn("0x1000", ["0x1100"]), fn("0x1100", ["0x1500"]), fn("0x1500", in_scope=False)])
    fake = scripted([resp(), resp()])
    walk(p, fake, tmp_path)
    assert "FUN_00101500, called on line 3: no summary (outside analysis scope)" in fake.calls[0]["user"]


def test_decompile_failed_callee_is_a_stub_and_never_sent(tmp_path):
    dead = fn("0x1300")
    dead.update(pseudo_c=None, decompile_failed=True)
    p = prog([fn("0x1100", ["0x1300"]), dead])
    fake = scripted([resp()])
    res = walk(p, fake, tmp_path)
    assert res["rows"]["0x1300"]["failure"] == "decompile_failed"
    assert len(fake.calls) == 1
    assert "FUN_00101300, called on line 3: no summary (decompilation failed)" in fake.calls[0]["user"]