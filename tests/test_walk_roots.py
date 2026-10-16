"""Phase 9 roots walk (D-036): only the roots' downward closure is walked, roots are always walked,
and every function in the closure gets exactly the prompt a whole-program walk gives it."""
from __future__ import annotations

import json

import pytest

from llm_fakes import FakeProvider, ok_response
from corpus_data import corpus_sha
from taintwalk.analysis.callgraph import build_graph, downward_closure, plan_walk
from taintwalk.analysis.walk_all import read_program_list, read_roots, walk_command
from taintwalk.analysis.walker import walk_program, walk_report
from taintwalk.config import REPO_ROOT, load_config

# A real corpus sha, so the name layer of the gate runs; the program contents are synthetic.
SHA = corpus_sha("tw-0015")  # committed manifest: same value, needs no runs/ data (D-043)
BASE = 0x100000


def name(addr: str) -> str:
    return f"FUN_{int(addr, 16) + BASE:08x}"


def fn(addr: str, callees=()) -> dict:
    calls = "".join(f"  {name(c)}(param_1);\n" for c in callees)
    return {"addr": addr, "ghidra_name": name(addr), "in_scope": True, "decompile_failed": False,
            "pseudo_c": f"void {name(addr)}(char *param_1)\n{{\n{calls}  return;\n}}\n",
            "callees": [{"kind": "internal", "addr": c} for c in callees]}


def prog() -> dict:
    """0x1000 -> 0x1100 -> 0x1200; 0x1300 -> 0x1100; 0x1400 isolated;
    0x1500 <-> 0x1600 recursive, reached from 0x1700."""
    return {"binary": {"sha256": SHA, "image_base": hex(BASE)}, "functions": [
        fn("0x1000", ["0x1100"]), fn("0x1100", ["0x1200"]), fn("0x1200"), fn("0x1300", ["0x1100"]),
        fn("0x1400"), fn("0x1500", ["0x1600"]), fn("0x1600", ["0x1500"]), fn("0x1700", ["0x1500"])]}


def resp():
    return ok_response(text=json.dumps({
        "params": [{"index": 0, "inferred_type": "char *", "role": "buffer"}],
        "sources": [], "sinks": [], "propagation": [], "returns_taint": False, "callee_effects": [],
        "verdict": {"reason": "r", "mechanism": "none", "region": "not_applicable",
                    "access": "not_applicable", "direction": "not_applicable",
                    "vulnerable": False, "confidence": 0.5}}))


def walk(fake, run_dir, **kw):
    return walk_program(fake, prog(), run_dir, max_chars=12000, max_iterations=3, log=lambda s: None, **kw)


def test_plan_without_roots_is_unchanged():
    p = plan_walk(build_graph(prog()))
    assert p.scope is None and p.roots == ()
    assert p.skipped_isolated == ("0x1400",)
    assert set(p.functions) == {"0x1000", "0x1100", "0x1200", "0x1300", "0x1500", "0x1600", "0x1700"}


def test_roots_plan_is_the_downward_closure_callees_first():
    p = plan_walk(build_graph(prog()), ("0x1000",))
    assert p.scope == ("0x1000", "0x1100", "0x1200") and p.roots == ("0x1000",)
    assert p.functions == ("0x1200", "0x1100", "0x1000") and p.skipped_isolated == ()


def test_isolated_root_is_walked():
    p = plan_walk(build_graph(prog()), ("0x1400",))
    assert p.functions == ("0x1400",) and p.skipped_isolated == ()


def test_recursive_component_inside_a_closure():
    p = plan_walk(build_graph(prog()), ("0x1700",))
    assert set(p.functions) == {"0x1500", "0x1600", "0x1700"}
    assert [c.members for c in p.order if c.recursive] == [("0x1500", "0x1600")]


def test_bad_roots_fail_closed():
    g = build_graph(prog())
    with pytest.raises(ValueError, match="not in-scope"):
        plan_walk(g, ("0x9999",))
    with pytest.raises(ValueError, match="at least one"):
        plan_walk(g, ())
    assert downward_closure(g, ("0x1300",)) == {"0x1300", "0x1100", "0x1200"}


def test_roots_walk_sends_only_prompts_a_full_walk_sends(tmp_path, capsys):
    full = FakeProvider([resp() for _ in range(30)], cache=None)
    walk(full, tmp_path / "full")
    part = FakeProvider([resp() for _ in range(30)], cache=None)
    res = walk(part, tmp_path / "roots", roots=("0x1000", "0x1700"))
    full_prompts = {c["user"] for c in full.calls}
    assert part.calls and all(c["user"] in full_prompts for c in part.calls)
    summaries = json.loads((tmp_path / "roots" / "summaries.json").read_text(encoding="utf-8"))
    assert sorted(summaries) == ["0x1000", "0x1100", "0x1200", "0x1500", "0x1600", "0x1700"]
    wj = json.loads((tmp_path / "roots" / "walk.json").read_text(encoding="utf-8"))
    assert wj["roots"] == ["0x1000", "0x1700"] and wj["closure_size"] == 6
    assert "roots" not in json.loads((tmp_path / "full" / "walk.json").read_text(encoding="utf-8"))
    capsys.readouterr()
    assert walk_report(res) == 0
    assert "roots              : 2  closure 6 functions" in capsys.readouterr().out


def test_list_file_carries_roots(tmp_path):
    d = tmp_path / "programs"
    d.mkdir()
    a, b = d / "tw-0001.json", d / "tw-0002.json"
    a.write_text("{}", encoding="utf-8")
    b.write_text("{}", encoding="utf-8")
    lst = tmp_path / "list.txt"
    lst.write_text(f"# c\n{a} 0x1a2b,0x1c3d\n{b}\n", encoding="utf-8")
    assert read_program_list(lst) == [a, b]
    assert read_roots(lst) == {"tw-0001": ("0x1a2b", "0x1c3d")}
    assert read_roots(d) == {}
    cmd = walk_command(a, tmp_path / "out", roots=("0x1a2b", "0x1c3d"))
    assert cmd[cmd.index("--roots") + 1] == "0x1a2b,0x1c3d"
    assert "--roots" not in walk_command(b, tmp_path / "out")
    lst.write_text(f"{a} 0xZZ\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bad roots"):
        read_roots(lst)


def test_cli_rejects_bad_roots(capsys):
    from taintwalk.cli import main
    assert main(["walk", "--all", "--programs", "x", "--run-dir", "y", "--roots", "0x1"]) == 2
    assert main(["walk", "--program", "nonexistent.json", "--roots", "zz"]) == 2