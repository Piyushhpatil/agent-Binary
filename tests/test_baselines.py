"""Rung rows (Phase 8, D-030): R1-R3 from program.json and flawfinder, R4-R7 from walk run dirs, and
score_rung() scoring every rung with the same D-008 code as score_runs()."""
from __future__ import annotations

import json
import shutil

import pytest

import taintwalk.eval.baselines as bl
from taintwalk.config import REPO_ROOT
from taintwalk.eval.baselines import INPUT_CALLS, RungError, llm_rung_doc, rule_rung_docs, unalias
from taintwalk.eval.metrics import score_rung, score_runs
from taintwalk.extract.report import load_manifest

P6 = REPO_ROOT / "runs" / "p6-gate"
LABELS = REPO_ROOT / "runs" / "p2-extract" / "labels"
PROGRAMS = REPO_ROOT / "runs" / "p2-extract" / "programs"
TINY_SHA = "c" * 64


def _fn(addr, pseudo, internal=(), external=()):
    return {"addr": addr, "in_scope": True, "pseudo_c": pseudo,
            "callees": [{"kind": "internal", "addr": a} for a in internal]
                       + [{"kind": "external", "name": n} for n in external]}


TINY = [
    _fn("0x1000", "void main(void)\n{\n  f1();\n  f2();\n  f3();\n}", internal=("0x1100", "0x1200", "0x1400")),
    _fn("0x1100", "void f1(char *d, char *s)\n{\n  strcpy(d, s);\n}", external=("strcpy",)),
    _fn("0x1200", 'int f2(void)\n{\n  int x;\n  __isoc23_fscanf(stdin, "%d", &x);\n  return x;\n}',
        external=("__isoc23_fscanf",)),
    _fn("0x1300", "int lonely(int a)\n{\n  return a;\n}"),
    _fn("0x1400", "int f3(int a)\n{\n  return a + 1;\n}"),
]


def _tiny(tmp_path):
    d = tmp_path / "programs"
    d.mkdir()
    (d / "tiny.json").write_text(json.dumps({"binary": {"sha256": TINY_SHA}, "functions": TINY}), encoding="utf-8")
    return d


def _kw():
    return {"manifest": load_manifest(), "labels_dir": LABELS, "programs_dir": PROGRAMS}


# ---- R1-R3 --------------------------------------------------------------------------------

def test_alias_adapter_and_input_list():
    assert unalias('__isoc23_fscanf(stdin, "%d", &x)') == 'fscanf(stdin, "%d", &x)'
    assert unalias("__isoc99_sscanf") == "sscanf" and unalias("x__isoc23_y") == "x__isoc23_y"
    assert len(INPUT_CALLS) == 26 and "rand" in INPUT_CALLS and "sscanf" not in INPUT_CALLS


def test_rule_rungs_on_a_tiny_program(tmp_path):
    docs = rule_rung_docs(_tiny(tmp_path), tmp_path / "work")
    r1, r2, r3 = (docs[k]["programs"][TINY_SHA] for k in ("R1", "R2", "R3"))
    assert set(r1) == set(r2) == set(r3) == {"0x1000", "0x1100", "0x1200", "0x1400"}  # 0x1300 is isolated
    assert r1["0x1100"]["outcome"] == "flagged" and r1["0x1100"]["score"] >= 1        # strcpy
    assert r1["0x1400"] == {"outcome": "clear", "score": 0, "verdict": None}
    assert r1["0x1000"]["outcome"] == "clear"
    assert [a for a, r in sorted(r2.items()) if r["outcome"] == "flagged"] == ["0x1200"]  # fscanf, via the adapter
    assert r3["0x1000"]["outcome"] == "flagged"
    assert r3["0x1000"]["score"] == max(r1[a]["score"] for a in ("0x1100", "0x1200", "0x1400"))
    assert r3["0x1400"] == {"outcome": "clear", "score": 0, "verdict": None} and r3["0x1100"] == r1["0x1100"]
    text = (tmp_path / "work" / "flawfinder" / "tiny" / "0x1200.c").read_text(encoding="utf-8")
    assert "fscanf(stdin" in text and "__isoc23_" not in text
    assert (docs["R1"]["score_scale"], docs["R2"]["score_scale"], docs["R3"]["score_scale"]) == ("ordinal", None, "ordinal")


def test_rule_rungs_are_deterministic(tmp_path):
    progs = _tiny(tmp_path)
    one = rule_rung_docs(progs, tmp_path / "w1")
    two = rule_rung_docs(progs, tmp_path / "w2")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_the_pinned_flawfinder_version_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(bl, "flawfinder_version", lambda exe: "2.0.19")
    with pytest.raises(RungError, match="pinned"):
        rule_rung_docs(_tiny(tmp_path), tmp_path / "work")


# ---- R4-R7 from a real walk (corpus-dependent: fails, never skips) ------------------------

def test_no_context_arm_takes_baseline_rows_where_the_walk_had_context():
    walk = json.loads((P6 / "walk.json").read_text(encoding="utf-8"))
    sha = walk["binary_sha256"]
    r5 = llm_rung_doc(P6, "R5")["programs"][sha]
    r4 = llm_rung_doc(P6, "R4")["programs"][sha]
    assert set(r4) == set(r5) == set(walk["functions"])
    with_ctx = {a for a, f in walk["functions"].items() if f["context_chars"]}
    assert with_ctx == set(walk["baseline"]) and len(with_ctx) == 12
    assert all(r4[a] == r5[a] for a in set(r5) - with_ctx)   # same prompt, same row
    assert any(r4[a] != r5[a] for a in with_ctx)             # context moved something (D-026 amendment)


def test_an_llm_rung_refuses_a_run_from_the_other_provider():
    with pytest.raises(RungError, match="anthropic"):
        llm_rung_doc(P6, "R7")


def test_the_no_context_arm_fails_closed(tmp_path):
    d = tmp_path / "run"
    shutil.copytree(P6, d)
    walk = json.loads((d / "walk.json").read_text(encoding="utf-8"))
    sha = walk["binary_sha256"]
    a = sorted(walk["baseline"])[0]
    (d / "baseline" / "summaries" / f"{sha[:12]}_{a}.json").unlink()
    with pytest.raises(RungError, match="missing"):
        llm_rung_doc(d, "R4")
    shutil.rmtree(d)
    shutil.copytree(P6, d)
    walk["functions"][a]["context_chars"] = 0
    (d / "walk.json").write_text(json.dumps(walk), encoding="utf-8")
    with pytest.raises(RungError, match="no callee block"):
        llm_rung_doc(d, "R4")


# ---- score_rung ---------------------------------------------------------------------------

def test_score_rung_scores_the_walk_arm_exactly_like_score_runs():
    kw = _kw()
    new = score_rung(llm_rung_doc(P6, "R5"), **kw)
    old = score_runs([P6], **kw)
    assert new["roots"] == old["roots"]
    assert new["strata"] == old["strata"]
    assert new["by_class"] == old["by_class"] and new["by_flow"] == old["by_flow"]
    assert new["diagnostics"] == old["diagnostics"] and new["roots_not_walked"] == 0


def test_rule_rungs_are_scored_on_the_same_roots(tmp_path):
    progs = tmp_path / "programs"
    progs.mkdir()
    shutil.copy(PROGRAMS / "tw-0015.json", progs / "tw-0015.json")
    docs = rule_rung_docs(progs, tmp_path / "work")
    kw = _kw()
    walk_roots = [(r["case_id"], r["addr"]) for r in score_runs([P6], **kw)["roots"]]
    for doc in docs.values():
        s = score_rung(doc, **kw)
        assert [(r["case_id"], r["addr"]) for r in s["roots"]] == walk_roots
        assert s["roots_not_walked"] == 0 and s["strata"]["pooled"]["typed"] is None
    assert score_rung(docs["R2"], **kw)["strata"]["pooled"]["confidence"] is None
    c1 = score_rung(docs["R1"], **kw)["strata"]["pooled"]["confidence"]
    assert c1["ece"] is None and c1["bins"] == []