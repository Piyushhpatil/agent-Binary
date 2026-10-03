"""Phase 9 scorer (D-036, D-038, D-040) on a synthetic real-code corpus: three included pairs, one excluded.

  rp-01  root with a callee   R5 F/C pair-correct   R4 F/F both-vulnerable   post gains a literal
  rp-02  no callee block      R4 = R5 = C/C both-clear                        (D-038 item 4)
  rp-03  root with a callee   R5 A/F abstained (context_overflow)   R4 C/A abstained (max_tokens)
                              its callee holds 2 indirect call sites
  rp-04  excluded at S6; its binaries do not exist and must never be read
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.eval.metrics import _cell, confusion
from taintwalk.eval.real_score import (
    BEGIN,
    END,
    PAIR_OUTCOMES,
    RealScoreError,
    dumps,
    load_p8,
    load_roots,
    pair_outcome,
    r4_doc,
    r5_doc,
    score_real,
    splice,
)

PROV = {"provider": "ollama", "model": "ornith:9b"}
PV = "v2"
SHA = {f"rw-000{i}": f"{i}" * 64 for i in range(1, 7)}
ROOT = {"rp-01": "0x1000", "rp-02": "0x2000", "rp-03": "0x3000"}
CALLEE = {"rp-01": "0x1100", "rp-02": None, "rp-03": "0x3100"}
CASES = {"rp-01": ("rw-0001", "rw-0002"), "rp-02": ("rw-0003", "rw-0004"), "rp-03": ("rw-0005", "rw-0006")}
# pair -> rung -> (pre outcome, post outcome); "A:<why>" abstains
OUT = {
    "rp-01": {"R1": ("F", "F"), "R2": ("C", "C"), "R3": ("F", "F"), "R4": ("F", "F"), "R5": ("F", "C")},
    "rp-02": {"R1": ("C", "C"), "R2": ("C", "C"), "R3": ("C", "C"), "R4": ("C", "C"), "R5": ("C", "C")},
    "rp-03": {"R1": ("F", "C"), "R2": ("C", "C"), "R3": ("F", "C"), "R4": ("C", "A:max_tokens"),
              "R5": ("A:context_overflow", "F")},
}
CTX = {"rp-01": 120, "rp-02": 0, "rp-03": 90}


def _verdict(vulnerable: bool, conf: float = 0.8) -> dict:
    return {"reason": "r", "mechanism": "out_of_bounds_access" if vulnerable else "none",
            "region": "heap" if vulnerable else "not_applicable",
            "access": "write" if vulnerable else "not_applicable",
            "direction": "past_end" if vulnerable else "not_applicable",
            "vulnerable": vulnerable, "confidence": conf}


def _record(name: str, addr: str, vulnerable: bool) -> dict:
    return {"schema_version": 1, "function": name, "address": addr,
            "summary": {"params": [], "sources": [], "sinks": [], "propagation": [], "returns_taint": False,
                        "callee_effects": [], "verdict": _verdict(vulnerable)}}


def _name(addr: str) -> str:
    return f"FUN_{int(addr, 16) + 0x100000:08x}"


def _fn(addr, pseudo, internal=(), external=(), indirect=0) -> dict:
    return {"addr": addr, "in_scope": True, "ghidra_name": _name(addr), "pseudo_c": pseudo,
            "indirect_call_sites": indirect,
            "callees": [{"kind": "internal", "addr": a} for a in internal]
                       + [{"kind": "external", "name": n} for n in external]}


def _program(pair: str, side: str) -> dict:
    root, callee = ROOT[pair], CALLEE[pair]
    lit = '  puts("too long");\n' if (pair, side) == ("rp-01", "post") else ""
    body = f"  {_name(callee)}(p);\n" if callee else "  return;\n"
    fns = [_fn(root, f"void {_name(root)}(char *p)\n{{\n{lit}{body}}}", internal=(callee,) if callee else ()),
           _fn("0x9000", f"int main(void)\n{{\n  {_name(root)}(0);\n  return 0;\n}}", internal=(root,))]
    if callee:
        fns.append(_fn(callee, f"void {_name(callee)}(char *d, char *s)\n{{\n  strcpy(d, s);\n}}",
                       external=("strcpy",), indirect=2 if pair == "rp-03" else 0))
    return {"binary": {"sha256": SHA[CASES[pair][side == "post"]]}, "functions": fns}


def _manifest() -> dict:
    pairs, entries = [], []
    for i, pair in enumerate(sorted(ROOT), 1):
        pre, post = CASES[pair]
        pairs.append({"pair_id": pair, "cve": f"CVE-2020-{1000 + i}", "aliases": [], "project": "proj",
                      "root": f"root_{i}", "file": "a.c", "pre": pre, "post": post,
                      "pre_addr": ROOT[pair], "post_addr": ROOT[pair], "excluded_by": None})
        for case, label in ((pre, "bad"), (post, "good")):
            entries.append({"case_id": case, "stripped_sha256": SHA[case],
                            "functions": [{"name": f"root_{i}", "addr": int(ROOT[pair], 16), "addr_hex": ROOT[pair],
                                           "label": label, "role": "root", "pair": pair}]})
    pairs.append({"pair_id": "rp-04", "cve": "CVE-2020-2000", "aliases": [], "project": "proj", "root": "gone",
                  "file": "b.c", "pre": "rw-0007", "post": "rw-0008", "pre_addr": "0x4000", "post_addr": "0x4000",
                  "excluded_by": "S6"})
    return {"pairs": pairs, "entries": entries}


def _outcome(code: str) -> tuple[str, str | None]:
    if code.startswith("A:"):
        return "abstain", code[2:]
    return ("flagged" if code == "F" else "clear"), None


def _build(tmp_path) -> dict:
    """Write the whole corpus: manifest, programs, R4 rows, walk run dirs, Phase 8 scores."""
    d = {k: tmp_path / k for k in ("programs", "r4", "walk", "p8")}
    for p in d.values():
        p.mkdir()
    (d["r4"] / "summaries").mkdir()
    (tmp_path / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    for pair in ROOT:
        for k, side in enumerate(("pre", "post")):
            case = CASES[pair][k]
            sha, root, callee = SHA[case], ROOT[pair], CALLEE[pair]
            (d["programs"] / f"{case}.json").write_text(json.dumps(_program(pair, side)), encoding="utf-8")
            r4, r4_why = _outcome(OUT[pair]["R4"][k])
            (d["r4"] / "summaries" / f"{sha[:12]}_{root}.json").write_text(json.dumps({
                "binary_sha256": sha, "address": root, "function": _name(root), "provider": PROV,
                "prompt_version": PV, "status": "ok" if r4 != "abstain" else "failed", "failure": r4_why,
                "record": None if r4 == "abstain" else _record(_name(root), root, r4 == "flagged")}),
                encoding="utf-8")
            r5, r5_why = _outcome(OUT[pair]["R5"][k])
            fns = {root: {"function": _name(root), "status": "ok" if r5 != "abstain" else "failed",
                          "failure": r5_why, "callees": [callee] if callee else [], "context_chars": CTX[pair]}}
            sums = {root: None if r5 == "abstain" else _record(_name(root), root, r5 == "flagged")}
            if callee:
                fns[callee] = {"function": _name(callee), "status": "ok", "failure": None, "callees": [],
                               "context_chars": 0}
                sums[callee] = _record(_name(callee), callee, True)
            run = d["walk"] / case
            run.mkdir()
            (run / "walk.json").write_text(json.dumps({
                "binary_sha256": sha, "prompt_version": PV, "callee_context_version": 1, "provider": PROV,
                "functions": fns}), encoding="utf-8")
            (run / "summaries.json").write_text(json.dumps(sums), encoding="utf-8")
    p8_rows = ([{"label": "bad", "cell": c} for c in ("TP", "TP", "FN")]
               + [{"label": "good", "cell": c} for c in ("TN", "TN", "TN", "TN", "FP")])
    for k in ("R1", "R2", "R3", "R4", "R5"):
        (d["p8"] / f"{k}.json").write_text(json.dumps(
            {"rung": k, "strata": {"pooled": {"primary": confusion(p8_rows)}}}), encoding="utf-8")
    return d


def _rule_docs() -> dict:
    docs = {}
    for k in ("R1", "R2", "R3"):
        programs: dict = {}
        for pair in ROOT:
            for i in (0, 1):
                o, _ = _outcome(OUT[pair][k][i])
                programs.setdefault(SHA[CASES[pair][i]], {})[ROOT[pair]] = {"outcome": o, "score": None, "verdict": None}
        docs[k] = {"rung": k, "kind": "rule", "definition": f"rule {k}", "identity": {}, "programs": programs}
    return docs


def _score(tmp_path, d=None, mutate=None):
    d = d or _build(tmp_path)
    if mutate:
        mutate(d)
    roots, progs = load_roots(json.loads((tmp_path / "manifest.json").read_text()), d["programs"])
    r4, r4_why = r4_doc(d["r4"], roots)
    r5, r5_why, ctx = r5_doc(d["walk"], roots)
    return score_real(roots, {**_rule_docs(), "R4": r4, "R5": r5}, reasons={"R4": r4_why, "R5": r5_why},
                      context_chars=ctx, progs=progs, p8=load_p8(d["p8"]), manifest_sha256="0" * 64)


# ---- rules ------------------------------------------------------------------------------------

def test_pair_outcomes_cover_every_combination():
    want = {("flagged", "clear"): "pair_correct", ("flagged", "flagged"): "both_vulnerable",
            ("clear", "clear"): "both_clear", ("clear", "flagged"): "reversed"}
    for pre in ("flagged", "clear", "abstain"):
        for post in ("flagged", "clear", "abstain"):
            got = pair_outcome(pre, post)
            assert got == want.get((pre, post), "abstained")
            assert got in PAIR_OUTCOMES
    with pytest.raises(RealScoreError):
        pair_outcome("flagged", "maybe")


def test_cells_are_phase8s_d008_cells():
    assert [_cell("bad", o) for o in ("flagged", "clear", "abstain")] == ["TP", "FN", "FN_abstain"]
    assert [_cell("good", o) for o in ("flagged", "clear", "abstain")] == ["FP", "TN", "abstain"]


# ---- the synthetic corpus -------------------------------------------------------------------

def test_scores_every_rung_at_every_root(tmp_path):
    s = _score(tmp_path)
    assert s["corpus"] == {"pairs": 3, "roots": 6, "projects": {"proj": 3}, "no_callee_pairs": 1}
    r5 = s["rungs"]["R5"]["primary"]
    assert r5["cells"] == {"TP": 1, "FN": 1, "FN_abstain": 1, "FP": 1, "TN": 2, "abstain": 0}
    assert (r5["recall"]["k"], r5["recall"]["n"]) == (1, 3)
    assert (r5["specificity"]["k"], r5["specificity"]["n"]) == (2, 3)
    assert (r5["coverage"]["k"], r5["coverage"]["n"]) == (5, 6)
    assert s["rungs"]["R4"]["primary"]["cells"] == {"TP": 1, "FN": 2, "FN_abstain": 0, "FP": 1, "TN": 1, "abstain": 1}
    assert s["abstentions"] == {"R4": {"max_tokens": 1}, "R5": {"context_overflow": 1}}
    assert s["base_rate"]["phase9"]["value"] == 0.5 and s["base_rate"]["phase8"]["value"] == 0.375


def test_pair_outcomes_and_the_no_callee_split(tmp_path):
    s = _score(tmp_path)
    po = s["pair_outcomes"]
    assert {o: po["all"]["R5"][o] for o in PAIR_OUTCOMES} == {
        "pair_correct": 1, "both_vulnerable": 0, "both_clear": 1, "reversed": 0, "abstained": 1}
    assert {o: po["all"]["R4"][o] for o in PAIR_OUTCOMES} == {
        "pair_correct": 0, "both_vulnerable": 1, "both_clear": 1, "reversed": 0, "abstained": 1}
    assert po["no_callee"]["R5"]["pairs"] == 1 and po["no_callee"]["R5"]["both_clear"] == 1
    assert po["with_callees"]["R5"]["pairs"] == 2 and po["with_callees"]["R5"]["pair_correct"] == 1
    assert po["all"]["R5"]["pair_correct_rate"]["k"] == 1 and po["all"]["R5"]["pair_correct_rate"]["n"] == 3
    assert [p["pair_id"] for p in s["pairs"]] == ["rp-01", "rp-02", "rp-03"]       # rp-04 excluded, never read
    assert [p["no_callee"] for p in s["pairs"]] == [False, True, False]


def test_gap_literal_gain_and_indirect_calls(tmp_path):
    s = _score(tmp_path)
    g = s["gap"]["R5"]
    assert g["recall"]["phase8"]["value"] == pytest.approx(2 / 3, abs=1e-6)
    assert g["recall"]["delta"] == pytest.approx(1 / 3 - 2 / 3, abs=1e-5)
    assert g["specificity"]["delta"] == pytest.approx(2 / 3 - 4 / 5, abs=1e-5)
    assert set(g) == {"recall", "specificity", "precision", "f1"}
    assert s["literal_gain"]["post_roots_gaining"] == 1
    assert s["pairs"][0]["literals_gained"] == ['"too long"']
    assert s["literal_gain"]["post_outcomes"]["R5"] == {"flagged": 0, "clear": 1, "abstain": 0}
    assert s["indirect_call_sites"] == {"roots_with_any": 2, "total_over_root_closures": 4}
    assert s["pairs"][2]["closure"] == {"pre": 2, "post": 2}
    assert s["pairs"][1]["closure"] == {"pre": 1, "post": 1}


def test_the_score_is_deterministic(tmp_path):
    d = _build(tmp_path)
    assert dumps(_score(tmp_path, d)) == dumps(_score(tmp_path, d))


# ---- failing closed ---------------------------------------------------------------------------

def test_no_callee_roots_must_get_identical_r4_and_r5_rows(tmp_path):
    def flip(d):
        p = d["r4"] / "summaries" / f"{SHA['rw-0003'][:12]}_0x2000.json"
        row = json.loads(p.read_text())
        row["record"] = _record(_name("0x2000"), "0x2000", True)
        p.write_text(json.dumps(row))
    with pytest.raises(RealScoreError, match="no callee block"):
        _score(tmp_path, mutate=flip)


def test_missing_rows_fail_closed(tmp_path):
    d = _build(tmp_path)
    shutil.rmtree(d["walk"] / "rw-0006")
    with pytest.raises(RealScoreError, match="no walk row for rp-03 post"):
        _score(tmp_path, d)
    (d["r4"] / "summaries" / f"{SHA['rw-0001'][:12]}_0x1000.json").unlink()
    with pytest.raises(RealScoreError, match="R4: .* is missing"):
        _score(tmp_path, d)


def test_r4_must_match_r5s_provider_and_prompt_version(tmp_path):
    def other_model(d):
        for p in (d["r4"] / "summaries").glob("*.json"):
            row = json.loads(p.read_text())
            row["provider"] = {"provider": "ollama", "model": "other:7b"}
            p.write_text(json.dumps(row))

    def mixed(d):
        p = sorted((d["r4"] / "summaries").glob("*.json"))[0]
        row = json.loads(p.read_text())
        row["prompt_version"] = "v1"
        p.write_text(json.dumps(row))

    for sub, mutate, msg in (("a", other_model, "different providers"), ("b", mixed, "never pooled")):
        (tmp_path / sub).mkdir()
        with pytest.raises(RealScoreError, match=msg):
            _score(tmp_path / sub, mutate=mutate)


def test_the_manifest_label_is_rechecked(tmp_path):
    d = _build(tmp_path)
    m = json.loads((tmp_path / "manifest.json").read_text())
    m["entries"][0]["functions"][0]["label"] = "good"
    with pytest.raises(RealScoreError, match="does not label"):
        load_roots(m, d["programs"])


# ---- RESULTS.md -------------------------------------------------------------------------------

def test_splice_appends_once_then_replaces_in_place(tmp_path):
    p = tmp_path / "RESULTS.md"
    p.write_text("# Results\n\nPhase 8 text.\n", encoding="utf-8")
    splice(p, "## Phase 9\n\nfirst\n")
    once = p.read_text(encoding="utf-8")
    assert once.startswith("# Results\n\nPhase 8 text.\n\n" + BEGIN) and once.endswith(END + "\n")
    splice(p, "## Phase 9\n\nfirst\n")
    assert p.read_text(encoding="utf-8") == once
    splice(p, "## Phase 9\n\nsecond\n")
    t = p.read_text(encoding="utf-8")
    assert "second" in t and "first" not in t and t.count(BEGIN) == t.count(END) == 1
    p.write_text(t + BEGIN + "\n", encoding="utf-8")
    with pytest.raises(RealScoreError, match="malformed"):
        splice(p, "x")


def _cli(*args):
    """In a subprocess, as Phase 8's CLI tests do: other tests in this process load taintwalk.llm."""
    return subprocess.run([sys.executable, "-m", "taintwalk.eval.real_score", *map(str, args)], cwd=REPO_ROOT,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def test_command_line_end_to_end(tmp_path):
    """The full entry point, R1-R3 included (flawfinder, as in Phase 8's tests)."""
    d = _build(tmp_path)
    results = tmp_path / "RESULTS.md"
    results.write_text("# Results\n", encoding="utf-8")
    args = ("--manifest", tmp_path / "manifest.json", "--programs", d["programs"], "--r4", d["r4"],
            "--walk", d["walk"], "--p8-scores", d["p8"], "--out", tmp_path / "eval", "--results-md", results)
    r = _cli(*args)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REAL EVAL OK: 3 pairs, 6 roots, rungs R1 R2 R3 R4 R5" in r.stdout
    assert "provider modules loaded: none" in r.stdout
    first = (tmp_path / "eval" / "real.json").read_bytes()
    md = results.read_text(encoding="utf-8")
    assert md.count(BEGIN) == 1 and "## Phase 9: real-code generalization (held out)" in md
    assert all((tmp_path / "eval" / "rules" / f"R{i}.json").exists() for i in (1, 2, 3))
    r = _cli(*args)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "eval" / "real.json").read_bytes() == first
    assert results.read_text(encoding="utf-8") == md
    shutil.rmtree(d["walk"] / "rw-0001")
    r = _cli(*args)
    assert r.returncode == 1
    assert "REAL EVAL FAIL: R5: no walk row for rp-01 pre" in r.stdout