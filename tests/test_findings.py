"""analysis/findings.py: label-free findings from persisted walk outputs (Phase 7, D-008)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from taintwalk.analysis.findings import FindingsError, build_findings, write_findings
from taintwalk.config import REPO_ROOT
from taintwalk.util.leakcheck import assert_clean

SHA = "ab" * 32


def _summary(*, vulnerable: bool, mechanism: str = "none", sink: bool = False,
             guarded: bool = False, flow: bool = False) -> dict:
    return {
        "params": [{"index": 0, "inferred_type": "char *", "role": "buffer"}],
        "sources": [],
        "sinks": ([{"sink_kind": "call_arg", "callee": "strcpy", "evidence_line": 3, "tainted_args": [],
                    "guarded": guarded, "guard_expr": "", "confidence": 0.8}] if sink else []),
        "propagation": ([{"src": "param:0", "dst": "sink:0", "sanitized": False}] if flow else []),
        "returns_taint": False,
        "callee_effects": [],
        "verdict": {"reason": "test", "mechanism": mechanism,
                    "region": "stack" if vulnerable else "not_applicable",
                    "access": "write" if vulnerable else "not_applicable",
                    "direction": "past_end" if vulnerable else "not_applicable",
                    "vulnerable": vulnerable, "confidence": 0.7},
    }


def _fn(name: str, callees=(), status: str = "ok", failure: str | None = None) -> dict:
    return {"function": name, "callees": list(callees), "status": status, "failure": failure}


def _rec(addr: str, name: str, summary: dict) -> dict:
    return {"schema_version": 1, "function": name, "address": addr, "summary": summary}


def _run(tmp_path: Path, fns: dict, summaries: dict, name: str = "run") -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / "walk.json").write_text(json.dumps({
        "binary_sha256": SHA, "prompt_version": 2, "callee_context_version": 1,
        "provider": {"provider": "fake"}, "functions": fns}), encoding="utf-8")
    (d / "summaries.json").write_text(json.dumps(summaries), encoding="utf-8")
    return d


def test_rows_verdicts_and_trail(tmp_path):
    oob = "out_of_bounds_access"
    fns = {
        "0x100": _fn("FUN_00100100", ["0x200", "0x300"]),
        "0x200": _fn("FUN_00100200", ["0x250"]),
        "0x250": _fn("FUN_00100250"),
        "0x300": _fn("FUN_00100300"),
        "0x400": _fn("FUN_00100400", status="max_tokens", failure="max_tokens"),
    }
    summaries = {
        "0x100": _rec("0x100", "FUN_00100100", _summary(vulnerable=True, mechanism=oob)),
        "0x200": _rec("0x200", "FUN_00100200", _summary(vulnerable=False)),
        "0x250": _rec("0x250", "FUN_00100250", _summary(vulnerable=True, mechanism=oob, sink=True, flow=True)),
        "0x300": _rec("0x300", "FUN_00100300", _summary(vulnerable=False, sink=True, guarded=True)),
        "0x400": None,
    }
    doc = build_findings(_run(tmp_path, fns, summaries))
    rows = doc["findings"]
    by = {r["address"]: r for r in rows}
    assert [r["address"] for r in rows] == ["0x100", "0x200", "0x250", "0x300", "0x400"]
    assert doc["walked"] == 5 and doc["no_summary"] == 1 and doc["binary_sha256"] == SHA
    sink = [{"index": 0, "sink_kind": "call_arg", "callee": "strcpy", "evidence_line": 3}]
    deep = {"address": "0x250", "function": "FUN_00100250", "vulnerable": True, "mechanism": oob,
            "conditional": True, "sinks": sink}
    root = by["0x100"]
    assert (root["status"], root["vulnerable"], root["mechanism"], root["conditional"]) == ("ok", True, oob, False)
    assert root["sinks"] == [] and root["source_kinds"] == []
    assert root["trail"] == [{**deep, "depth": 2}]          # the forwarder 0x200 does not cut it
    assert by["0x200"]["trail"] == [{**deep, "depth": 1}]
    assert by["0x250"]["conditional"] is True and by["0x250"]["sinks"] == sink
    assert by["0x300"]["sinks"] == [] and by["0x300"]["trail"] == []      # guarded sink
    failed = by["0x400"]
    assert (failed["status"], failed["failure"]) == ("no_summary", "max_tokens")
    assert failed["vulnerable"] is None and failed["mechanism"] is None and failed["conditional"] is None


def test_output_is_deterministic_and_numerically_ordered(tmp_path):
    fns = {"0x1a0": _fn("FUN_001001a0"), "0x9f": _fn("FUN_0010009f", ["0x1a0"])}
    summaries = {"0x1a0": _rec("0x1a0", "FUN_001001a0", _summary(vulnerable=False)),
                 "0x9f": _rec("0x9f", "FUN_0010009f", _summary(vulnerable=False))}
    d = _run(tmp_path, fns, summaries)
    first = write_findings(d).read_bytes()
    second = write_findings(d).read_bytes()
    assert first == second
    text = first.decode("utf-8")
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True) + "\n"
    assert [r["address"] for r in json.loads(text)["findings"]] == ["0x9f", "0x1a0"]


def test_fails_closed_on_inconsistent_walk_outputs(tmp_path):
    ok = _rec("0x100", "FUN_00100100", _summary(vulnerable=False))
    cases = {
        "missing": ({"0x100": _fn("FUN_00100100"), "0x200": _fn("FUN_00100200")}, {"0x100": ok},
                    "no summaries.json entry"),
        "null_but_ok": ({"0x100": _fn("FUN_00100100")}, {"0x100": None}, "record is absent"),
        "wrong_address": ({"0x200": _fn("FUN_00100200")}, {"0x200": ok}, "holds the record of 0x100"),
    }
    for name, (fns, summaries, msg) in cases.items():
        with pytest.raises(FindingsError, match=msg):
            build_findings(_run(tmp_path, fns, summaries, name))
    with pytest.raises(FindingsError, match="walk.json is missing"):
        build_findings(tmp_path / "nowhere")


def test_trail_terminates_on_cycles(tmp_path):
    oob = "out_of_bounds_access"
    fns = {"0x10": _fn("FUN_00100010", ["0x20"]), "0x20": _fn("FUN_00100020", ["0x10"])}
    summaries = {a: _rec(a, fns[a]["function"], _summary(vulnerable=True, mechanism=oob, sink=True))
                 for a in fns}
    by = {r["address"]: r for r in build_findings(_run(tmp_path, fns, summaries))["findings"]}
    assert [(t["address"], t["depth"]) for t in by["0x10"]["trail"]] == [("0x20", 1)]
    assert [(t["address"], t["depth"]) for t in by["0x20"]["trail"]] == [("0x10", 1)]


def test_real_runs_are_complete_and_gate_clean():
    p7 = [p.parent for p in sorted((REPO_ROOT / "runs/p7-walk").glob("tw-*/walk.json"))]
    assert len(p7) == 12, "the D-028 shakedown walks are missing"
    for d in [REPO_ROOT / "runs/p6-gate", *p7]:
        doc = build_findings(d)
        walk = json.loads((d / "walk.json").read_text(encoding="utf-8"))
        assert doc["walked"] == len(walk["functions"]) == len(doc["findings"]), d.name
        assert_clean(json.dumps(doc, sort_keys=True), binary_sha256=doc["binary_sha256"])
    assert build_findings(REPO_ROOT / "runs/p6-gate")["walked"] == 13