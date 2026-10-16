"""eval/metrics.py: the D-008 scoring rules (Phase 7). Synthetic tests use hand-computed numbers;
the structural audit and the join test read the real corpus and fail, never skip, without it."""
from __future__ import annotations

import json
import random

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.eval.metrics import (
    ScoreError,
    audit_paths,
    confidence_metrics,
    confusion,
    graph_succ,
    judge_root,
    score_binary,
    score_runs,
    typed,
    wilson,
)
from taintwalk.extract.report import load_manifest

LABELS = REPO_ROOT / "runs/p2-extract/labels"
PROGRAMS = REPO_ROOT / "runs/p2-extract/programs"
SHA = "cd" * 32
OOB = "out_of_bounds_access"


def _f(addr, *, vul=None, mech="none", region="not_applicable", access="not_applicable",
       direction="not_applicable", conf=0.8, status="ok") -> dict:
    ok = status == "ok"
    return {"address": addr, "status": status,
            "vulnerable": vul if ok else None, "mechanism": mech if ok else None,
            "region": region if ok else None, "access": access if ok else None,
            "direction": direction if ok else None, "confidence": conf if ok else None}


def _lab(addr, label, role, scored=True) -> dict:
    return {"addr": addr, "label": label, "role": role, "scored": scored}


ENTRY = {"case_id": "tw-9001", "cwe": "CWE-121", "flow_variant": "41", "stratum": "external"}
SUCC = {"0x10": ("0x20",), "0x20": ("0x90",), "0x30": ("0x40",), "0x40": (), "0x50": ("0x60",),
        "0x60": (), "0x70": ("0x30", "0x50"), "0x80": ("0x10", "0x70"), "0x90": ()}
FUNCTIONS = [
    _lab("0x10", "bad", "entry"), _lab("0x20", "bad", "sink"),
    _lab("0x30", "good", "path"), _lab("0x40", "good", "sink"),
    _lab("0x50", "good", "path"), _lab("0x60", "good", "sink"),
    _lab("0x70", "good", "entry"), _lab("0x80", "harness", None, False),
    _lab("0x90", "support", None, False),
]
FINDINGS = {"binary_sha256": SHA, "findings": [
    _f("0x10", vul=True, mech=OOB, region="stack", access="write", direction="past_end", conf=0.9),
    _f("0x20", vul=True, mech="other"),
    _f("0x30", vul=False),
    _f("0x40", vul=True, mech="other"),
    _f("0x50", status="no_summary"),
    _f("0x60", vul=False),
    _f("0x70", vul=True, mech="other"),
    _f("0x80", vul=False),
    _f("0x90", vul=True, mech="other"),
]}
LABELS_DOC = {"program_sha256": SHA, "functions": FUNCTIONS}


def test_wilson_known_values():
    assert wilson(0, 0) is None
    assert wilson(5, 10) == pytest.approx([0.2366, 0.7634], abs=1e-4)
    assert wilson(0, 10) == pytest.approx([0.0, 0.2775], abs=1e-4)
    assert wilson(10, 10) == pytest.approx([0.7225, 1.0], abs=1e-4)


def test_path_roots_secondary_rule_and_diagnostics():
    roots, diags = score_binary(FINDINGS, LABELS_DOC, SUCC, ENTRY)
    by = {r["addr"]: r for r in roots}
    assert sorted(by) == ["0x10", "0x30", "0x50"]
    assert (by["0x10"]["cell"], by["0x10"]["exact_ok"], by["0x10"]["derived_cwe"]) == ("TP", True, "CWE-121")
    assert by["0x10"]["members"] == ["0x10", "0x20"]
    assert (by["0x30"]["cell"], by["0x30"]["secondary_cell"], by["0x30"]["members"]) == ("TN", "FP", ["0x30", "0x40"])
    assert (by["0x50"]["cell"], by["0x50"]["secondary_cell"]) == ("abstain", "abstain")
    assert by["0x10"]["score"] == 0.9 and by["0x30"]["score"] == 0.2
    p = confusion(roots, "cell")
    assert (p["positives"], p["negatives"]) == (1, 2)
    assert p["cells"] == {"TP": 1, "FN": 0, "FN_abstain": 0, "FP": 0, "TN": 1, "abstain": 1}
    assert p["precision"]["value"] == 1.0 and p["recall"]["value"] == 1.0
    assert p["specificity"]["value"] == 0.5          # the abstaining good root is not a TN
    assert p["coverage"]["value"] == pytest.approx(2 / 3, abs=1e-6)
    s = confusion(roots, "secondary_cell")
    assert s["cells"] == {"TP": 1, "FN": 0, "FN_abstain": 0, "FP": 1, "TN": 0, "abstain": 1}
    assert s["precision"]["value"] == 0.5 and s["specificity"]["value"] == 0.0
    d = {(x["label"], x["role"]): x["outcome"] for x in diags}
    assert d[("good", "entry")] == "flagged" and d[("support", None)] == "flagged"
    assert sorted(x["addr"] for x in diags) == ["0x20", "0x40", "0x60", "0x70", "0x80", "0x90"]


def test_typed_ladder_and_right_bug_wrong_cwe():
    cwe = "CWE-122"
    rows = [
        judge_root("bad", _f("a", vul=True, mech=OOB, region="heap", access="write", direction="past_end"), cwe),
        judge_root("bad", _f("b", vul=True, mech=OOB, region="stack", access="write", direction="past_end"), cwe),
        judge_root("bad", _f("c", vul=True, mech=OOB, region="unknown", access="write", direction="past_end"), cwe),
        judge_root("bad", _f("d", vul=True, mech="integer_overflow"), cwe),
        judge_root("bad", _f("e", vul=False), cwe),
        judge_root("good", _f("f", vul=True, mech=OOB, region="heap", access="write", direction="past_end"), cwe),
    ]
    t = typed(rows)
    got = {lvl: (t[lvl]["tp"], t[lvl]["precision"]["value"], t[lvl]["recall"]["value"])
           for lvl in ("detection", "mechanism", "exact")}
    assert got == {"detection": (4, 0.8, 0.8), "mechanism": (3, 0.6, 0.6), "exact": (1, 0.2, 0.2)}
    assert t["right_bug_wrong_cwe"] == {"ambiguous": 1, "right_mechanism_wrong_field": 1,
                                        "wrong_mechanism": 1, "total": 3}


def test_a_missing_summary_never_raises_recall_specificity_or_coverage():
    rng = random.Random(7)
    for _ in range(300):
        rows = []
        for i in range(rng.randint(2, 12)):
            label = rng.choice(("bad", "good"))
            state = rng.choice(("flag", "clear", "none"))
            f = None if state == "none" else _f(str(i), vul=(state == "flag"),
                                                 mech="other" if state == "flag" else "none")
            rows.append(judge_root(label, f, "CWE-121"))
        answered = [i for i, r in enumerate(rows) if r["outcome"] != "abstain"]
        if not answered:
            continue
        before = confusion(rows)
        k = rng.choice(answered)
        rows[k] = judge_root(rows[k]["label"], None, "CWE-121")
        after = confusion(rows)
        for m in ("recall", "specificity", "coverage"):
            if before[m]["value"] is not None:
                assert after[m]["value"] <= before[m]["value"], (m, before[m], after[m])


def test_confidence_auroc_with_ties_and_ece():
    rows = [
        judge_root("bad", _f("a", vul=True, mech="other", conf=0.9), "CWE-121"),     # s 0.9
        judge_root("bad", _f("b", vul=False, conf=0.5), "CWE-121"),                  # s 0.5
        judge_root("good", _f("c", vul=True, mech="other", conf=0.5), "CWE-121"),    # s 0.5
        judge_root("good", _f("d", vul=False, conf=0.9), "CWE-121"),                 # s 0.1
        judge_root("good", None, "CWE-121"),                                          # abstains: excluded
    ]
    c = confidence_metrics(rows)
    assert c["answered"] == 4
    assert c["auroc"] == 0.875
    assert c["ece"] == pytest.approx(0.05, abs=1e-6)
    assert [(b["bin"], b["n"]) for b in c["bins"]] == [([0.1, 0.2], 1), ([0.5, 0.6], 2), ([0.9, 1.0], 1)]


def test_joins_fail_closed():
    with pytest.raises(ScoreError, match="no label entry"):
        score_binary({"binary_sha256": SHA, "findings": [*FINDINGS["findings"], _f("0xa0", vul=False)]},
                     LABELS_DOC, {**SUCC, "0xa0": ()}, ENTRY)
    with pytest.raises(ScoreError, match="not an in-scope function"):
        score_binary(FINDINGS, LABELS_DOC, {k: v for k, v in SUCC.items() if k != "0x30"}, ENTRY)
    two_bad = {"program_sha256": SHA, "functions": [*FUNCTIONS, _lab("0xb0", "bad", "entry")]}
    with pytest.raises(ScoreError, match="bad path roots"):
        score_binary(FINDINGS, two_bad, {**SUCC, "0xb0": ()}, ENTRY)


@pytest.mark.corpus
def test_score_runs_fails_closed_on_a_label_file_for_another_binary(tmp_path):
    run = REPO_ROOT / "runs/p6-gate"
    sha = json.loads((run / "walk.json").read_text(encoding="utf-8"))["binary_sha256"]
    manifest = load_manifest()
    case = next(e["case_id"] for e in manifest["entries"] if e["stripped_sha256"] == sha)
    lab = json.loads((LABELS / f"{case}.json").read_text(encoding="utf-8"))
    lab["program_sha256"] = "0" * 64
    (tmp_path / f"{case}.json").write_text(json.dumps(lab), encoding="utf-8")
    with pytest.raises(ScoreError, match="label file"):
        score_runs([run], manifest=manifest, labels_dir=tmp_path, programs_dir=PROGRAMS)


@pytest.mark.corpus
def test_path_structure_audit_over_the_whole_corpus():
    totals = {"binaries": 0, "bad_roots": 0, "good_roots": 0}
    problems = []
    for e in load_manifest()["entries"]:
        lab = json.loads((LABELS / f"{e['case_id']}.json").read_text(encoding="utf-8"))
        prog = json.loads((PROGRAMS / f"{e['case_id']}.json").read_text(encoding="utf-8"))
        assert lab["program_sha256"] == prog["binary"]["sha256"] == e["stripped_sha256"], e["case_id"]
        a = audit_paths(graph_succ(prog), lab["functions"])
        totals["binaries"] += 1
        totals["bad_roots"] += a["bad_roots"]
        totals["good_roots"] += a["good_roots"]
        if (a["bad_roots"] != 1 or a["good_roots"] < 1
                or any(a[k] for k in ("orphans", "shared", "nested", "dispatchers_in_paths"))):
            problems.append((e["case_id"], e["flow_variant"], a))
    assert problems == [], problems[:5]
    assert totals == {"binaries": 240, "bad_roots": 240, "good_roots": 396}