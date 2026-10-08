"""Phase 10 scorer (D-042): row shape, the fail-closed rules, rendering and an idempotent splice.

What is NOT tested here: score() end to end. It calls check_no_provider() first, and pytest has
taintwalk.llm loaded by other modules, so score() can only run in a subprocess -- exactly as
tests/test_score.py does for `taintwalk score`. The end-to-end run arrives with the real dev run
dirs in mini-step 10.
"""
import json
import pathlib
import subprocess
import sys

import pytest

from taintwalk.eval import agent_score as A
from taintwalk.eval.agent_score import (
    AgentScoreError, _abstain, _cells, _dist, _row, _stem, check_floor, check_no_provider,
    load_cases, render, splice,
)
from taintwalk.eval.metrics import row_from_finding


# --------------------------------------------------------------------------- isolation

def test_importing_the_scorer_loads_no_provider_module():
    """Rule 3 has to hold for this module's own imports. Importing analyze_one for stem() pulled in
    taintwalk.llm and made the scorer fail on itself; a subprocess is the only honest check, since
    pytest has already imported llm for other tests."""
    out = subprocess.run(
        [sys.executable, "-c",
         "import taintwalk.eval.agent_score, sys;"
         "print(sorted(m for m in sys.modules if m.startswith('taintwalk.llm')))"],
        capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]", f"provider modules loaded on import: {out.stdout.strip()}"


def test_stem_matches_the_real_one():
    """_stem is duplicated from analysis.analyze_one to keep llm out of the import graph, so it has
    to be pinned to the original or the R4 baseline rows are read from the wrong paths."""
    from taintwalk.analysis.analyze_one import stem
    for sha, addr in (("a" * 64, "0x1000"), ("0123456789abcdef" * 4, "0x1aba")):
        assert _stem(sha, addr) == stem(sha, addr)


def _record(vulnerable=True, conf=0.8):
    return {"summary": {"verdict": {
        "reason": "r", "mechanism": "out_of_bounds_access" if vulnerable else "none",
        "region": "stack" if vulnerable else "not_applicable",
        "access": "write" if vulnerable else "not_applicable",
        "direction": "past_end" if vulnerable else "not_applicable",
        "vulnerable": vulnerable, "confidence": conf}}}


# --------------------------------------------------------------------------- rows

def test_row_matches_row_from_finding():
    """The scorer's row must be the shape metrics already consumes, or score_rung rejects it."""
    v = _record(vulnerable=True, conf=0.8)["summary"]["verdict"]
    finding = {"status": "ok", "vulnerable": True, "confidence": 0.8, **v}
    mine = _row(_record(vulnerable=True, conf=0.8))
    theirs = row_from_finding(finding)
    assert mine["outcome"] == theirs["outcome"] == "flagged"
    assert mine["score"] == theirs["score"] == 0.8
    assert set(mine) == set(theirs)


def test_row_score_is_one_minus_confidence_when_clear():
    r = _row(_record(vulnerable=False, conf=0.75))
    assert r["outcome"] == "clear" and r["score"] == 0.25


def test_no_record_is_an_abstention_never_clear():
    """D-008: a missing summary counts against recall; it is never 'not vulnerable'."""
    for empty in (None, {}, False):
        r = _row(empty)
        assert r["outcome"] == "abstain" and r["score"] is None and r["verdict"] is None


# --------------------------------------------------------------------------- fail-closed

def _agent_doc(addr_fields, cap=150000):
    return {"caps": {"max_tokens_per_root": cap}, "functions": addr_fields}


def _fn(metered=100, fetched=(), read=()):
    return {"metered_tokens": metered, "summaries_fetched": list(fetched),
            "code_read": list(read), "steps": 2, "calls": 2, "stop": "finish",
            "invalid_actions": 0, "repeated_actions": 0}


def _write_agent_dirs(root, per_policy):
    for policy, doc in per_policy.items():
        d = root / policy / "tw-0015"
        d.mkdir(parents=True, exist_ok=True)
        (d / "agent.json").write_text(json.dumps(doc), encoding="utf-8")


def _tables(a1, a2, r4):
    return {"A1": {"tw-0015": {"rows": a1}}, "A2": {"tw-0015": {"rows": a2}},
            "R4": {"tw-0015": {"rows": r4}}}


CASES = [("tw-0015", "0" * 64, ["0x1000"])]


def test_zero_fetch_root_must_equal_r4(tmp_path):
    """Rule 1, the floor. A root the agent gathered nothing for must carry R4's cell exactly;
    otherwise the harness itself is contributing to the result."""
    _write_agent_dirs(tmp_path, {"scripted": _agent_doc({"0x1000": _fn(fetched=())}),
                                 "llm": _agent_doc({"0x1000": _fn(fetched=())})})
    same = {"0x1000": {"outcome": "flagged"}}
    out = check_floor(tmp_path, CASES, _tables(same, same, same))
    assert out == {"zero_fetch_roots": 2, "zero_fetch_matched_r4": 2}

    differs = {"0x1000": {"outcome": "clear"}}
    with pytest.raises(AgentScoreError, match="zero-fetch"):
        check_floor(tmp_path, CASES, _tables(same, differs, same))


def test_a_root_that_fetched_is_not_required_to_match_r4(tmp_path):
    _write_agent_dirs(tmp_path, {"scripted": _agent_doc({"0x1000": _fn(fetched=("0x1100",))}),
                                 "llm": _agent_doc({"0x1000": _fn(read=("0x1100",))})})
    out = check_floor(tmp_path, CASES,
                      _tables({"0x1000": {"outcome": "clear"}}, {"0x1000": {"outcome": "clear"}},
                              {"0x1000": {"outcome": "flagged"}}))
    assert out["zero_fetch_roots"] == 0


def test_metered_total_over_cap_fails_closed(tmp_path):
    """Rule 2: the caps are the experiment's cost control; a run that broke them is not scorable."""
    _write_agent_dirs(tmp_path, {"scripted": _agent_doc({"0x1000": _fn(metered=10)}, cap=100),
                                 "llm": _agent_doc({"0x1000": _fn(metered=101)}, cap=100)})
    same = {"0x1000": {"outcome": "flagged"}}
    with pytest.raises(AgentScoreError, match="over cap"):
        check_floor(tmp_path, CASES, _tables(same, same, same))


def test_check_no_provider_both_directions():
    """Rule 3 (D-008 amendment). In pytest other modules have already imported taintwalk.llm, so
    the pass direction is only reachable with those entries removed -- which is why the real
    guarantee is a subprocess, not this test."""
    saved = {k: v for k, v in sys.modules.items() if k.startswith("taintwalk.llm")}
    try:
        for k in saved:
            del sys.modules[k]
        assert check_no_provider() == []
        sys.modules["taintwalk.llm.sentinel"] = object()
        with pytest.raises(AgentScoreError, match="provider modules loaded"):
            check_no_provider()
    finally:
        sys.modules.pop("taintwalk.llm.sentinel", None)
        sys.modules.update(saved)


# --------------------------------------------------------------------------- cells and stats

def test_cells_names_the_real_keys_when_the_shape_surprises_us():
    with pytest.raises(AgentScoreError, match=r"actual keys are \['FN', 'TP', 'oops'\]"):
        _cells({"strata": {"pooled": {"primary": {"TP": 1, "FN": 2, "oops": 3}}}}, "A2")
    with pytest.raises(AgentScoreError, match="no pooled stratum"):
        _cells({"strata": {"external": {"primary": {}}}}, "A2")


def test_abstain_sums_both_abstention_cells():
    assert _abstain({"FN_abstain": 3, "abstain": 4}) == 7     # bad-root and good-root abstentions
    assert _abstain({"abstain": 4}) == 4
    assert _abstain({}) == 0


def test_dist_percentiles():
    assert _dist([]) == {"n": 0, "median": None, "p90": None, "max": None, "total": 0}
    d = _dist([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    assert (d["n"], d["median"], d["p90"], d["max"], d["total"]) == (10, 5.5, 9, 10, 55)


# --------------------------------------------------------------------------- render and splice

CELL = {"TP": 10, "FN": 2, "FP": 9, "TN": 0, "FN_abstain": 2, "abstain": 3,
        "recall": 0.833, "specificity": 0.0, "precision": 0.526, "coverage": 0.792}
PROC = {"policy": "x", "roots": 35, "steps": _dist([1, 2, 3]),
        "metered_tokens": _dist([100, 200, 300]), "summaries_fetched": _dist([1, 1, 2]),
        "code_reads": _dist([0, 0, 1]), "stops": {"finish": 30, "max_actions": 5},
        "invalid_actions": 1, "repeated_actions": 2, "zero_fetch_roots": 4}
DOC = {
    "status": "development slice, not reportable (D-028)", "roots": 35,
    "cells": {r: CELL for r in A.RUNGS},
    "tests": {"alpha": 0.05, "family": 6, "missing": [], "holm_applied": True,
              "tests": {f"{c}-{lab}": {"comparison": c, "a": a, "b": b, "label": lab, "n": 12,
                                       "a_right": 7, "b_right": 6, "both": 5, "a_only": 2,
                                       "b_only": 1, "neither": 4, "p": 0.1234,
                                       "p_holm": 0.4936, "reject": False}
                        for c, a, b in A.P10_COMPARISONS for lab in ("bad", "good")}},
    "process": {"A1": PROC, "A2": PROC},
    "floor": {"zero_fetch_roots": 4, "zero_fetch_matched_r4": 4},
}


def test_render_has_one_row_per_rung_and_all_six_tests():
    s = render(DOC)
    assert s.startswith(A.BEGIN) and s.rstrip().endswith(A.END)
    # A1 and A2 head a row in the cells table AND in the process table, so scope to the first one
    cells_table = s.split("### Pre-registered tests")[0]
    for r in A.RUNGS:
        assert len([l for l in cells_table.splitlines() if l.startswith(f"| {r} |")]) == 1
    assert "| 10 | 2 | 9 | 0 | 5 |" in s          # TP FN FP TN, abstain = FN_abstain + abstain
    assert s.count("| A2 vs ") == 6


def test_splice_is_idempotent_and_leaves_phase_9_alone(tmp_path):
    """The gate runs the scorer twice and requires byte-identical output."""
    md = tmp_path / "RESULTS.md"
    md.write_text("# Results\n\n<!-- phase9:begin -->\nphase 9\n<!-- phase9:end -->\n",
                  encoding="utf-8")
    section = render(DOC)
    splice(md, section)
    first = md.read_bytes()
    splice(md, section)
    assert md.read_bytes() == first                       # no drift on a re-run
    splice(md, section.replace("Status:", "State:"))
    text = md.read_text(encoding="utf-8")
    assert text.count(A.BEGIN) == 1 and text.count(A.END) == 1
    assert "phase 9" in text and "State:" in text and "Status:" not in text


def test_load_cases_reads_paths_and_roots(tmp_path, monkeypatch):
    prog = tmp_path / "tw-0015.json"
    prog.write_text(json.dumps({"binary": {"sha256": "a" * 64}}), encoding="utf-8")
    lst = tmp_path / "programs.txt"
    lst.write_text(f"# a comment\n\n{prog} 0x1000,0x1100\n", encoding="utf-8")
    assert load_cases(lst) == [("tw-0015", "a" * 64, ["0x1000", "0x1100"])]

    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n", encoding="utf-8")
    with pytest.raises(AgentScoreError, match="no programs"):
        load_cases(empty)