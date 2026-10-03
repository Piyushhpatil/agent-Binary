"""Phase 9 gap-analysis tooling on the synthetic corpus of test_real_score (R5 outcomes there):

  rp-01  F/C   TP, TN                      nothing to code
  rp-02  C/C   FN (hand), TN
  rp-03  A/F   FN_abstain (mechanical: context overflow), FP (hand)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from taintwalk.analysis.prompts import CALLEE_HEADER
from taintwalk.config import REPO_ROOT
from taintwalk.eval.erroranalysis import CODEBOOK as D032
from taintwalk.eval.real_gap import (
    CODEBOOK,
    GapError,
    items_of,
    mechanical_code,
    source_diff,
    tally,
    worksheet,
)
from taintwalk.eval.real_score import dumps
from test_real_score import SHA, _build, _score

V1 = "int f(char *b, int n)\n{\n  b[n] = 0;\n  return n;\n}\n"
V2 = "int f(char *b, int n)\n{\n  if (n > 8) return -1;\n  b[n] = 0;\n  return n;\n}\n"


def _git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def _corpus(tmp_path) -> dict:
    """test_real_score's corpus, plus a project clone holding the fix, prompts, and real.json."""
    d = _build(tmp_path)
    repo = tmp_path / "src" / "proj"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "a.c").write_text(V1, encoding="utf-8")
    _git(repo, "add", "a.c")
    _git(repo, "commit", "-qm", "v1")
    (repo / "a.c").write_text(V2, encoding="utf-8")
    _git(repo, "commit", "-qam", "bound the index")
    fix = _git(repo, "rev-parse", "HEAD")
    m = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    for p in m["pairs"]:
        p["fix"] = fix
    (tmp_path / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    for case, addr, user in (("rw-0006", "0x3000", f"code\n\n{CALLEE_HEADER}\nFUN_00103100: vulnerable heap write"),
                             ("rw-0003", "0x2000", "code only")):
        prompts = d["walk"] / case / "prompts"
        prompts.mkdir()
        (prompts / f"{SHA[case][:12]}_{addr}.json").write_text(json.dumps({"user": user}), encoding="utf-8")
    (tmp_path / "real.json").write_text(dumps(_score(tmp_path, d)), encoding="utf-8")
    return {**d, "manifest": m, "src": tmp_path / "src", "fix": fix}


def _sheet(tmp_path, c):
    score = json.loads((tmp_path / "real.json").read_text(encoding="utf-8"))
    return worksheet(score, c["manifest"], walk_root=c["walk"], programs_dir=c["programs"], src_root=c["src"])


GOOD = {"rp-02/pre": {"code": "root only lacks a check", "note": "the fix guards a caller"},
        "rp-03/pre": {"code": "abstained: context overflow", "note": ""},
        "rp-03/post": {"code": "ignored guard", "note": "flags the bounded write"}}


# ---- codebook and items -----------------------------------------------------------------------

def test_codebook_is_d032_plus_the_preregistered_additions():
    assert CODEBOOK["FP"] == tuple(D032["FP"])
    assert set(D032["FN"]) < set(CODEBOOK["FN"]) and CODEBOOK["FN"][-1] == "other"
    assert set(CODEBOOK["FN"]) - set(D032["FN"]) == {
        "rand() treated as trusted", "declined a correct callee verdict", "root only lacks a check"}
    assert mechanical_code("context_overflow") == "abstained: context overflow"
    assert mechanical_code("max_tokens") == "abstained: max_tokens"


def test_items_are_the_r5_errors_at_the_roots(tmp_path):
    _corpus(tmp_path)
    items = items_of(json.loads((tmp_path / "real.json").read_text(encoding="utf-8")))
    assert [(i["id"], i["cell"], i["mechanical"]) for i in items] == [
        ("rp-02/pre", "FN", None),
        ("rp-03/pre", "FN_abstain", "abstained: context overflow"),
        ("rp-03/post", "FP", None)]


# ---- worksheet --------------------------------------------------------------------------------

def test_worksheet_carries_what_a_coder_needs(tmp_path):
    c = _corpus(tmp_path)
    text, items, template = _sheet(tmp_path, c)
    for pair in ("rp-01", "rp-02", "rp-03"):
        assert f"\n## {pair} " in text
    assert "+  if (n > 8) return -1;" in text                        # the fix's source diff
    assert '+  puts("too long");' in text                            # the decompiled diff of rp-01
    assert text.count("- code: ____   note: ____") == 2              # rp-02/pre and rp-03/post
    assert "- code: `abstained: context overflow` (mechanical)" in text
    assert "FUN_00103100: vulnerable heap write" in text             # rp-03/post's callee block
    assert "- no summary: context_overflow" in text                  # rp-03/pre
    assert template["items"] == {i["id"]: {"code": i["mechanical"], "note": ""} for i in items}
    assert _sheet(tmp_path, c)[0] == text                            # deterministic


def test_source_diff_degrades_to_a_note(tmp_path):
    c = _corpus(tmp_path)
    assert source_diff(c["src"], "nope", c["fix"]).startswith("(no clone at")
    assert source_diff(c["src"], "proj", "0" * 40).startswith("(git show 000000000000 failed")


# ---- tally ------------------------------------------------------------------------------------

def test_tally_counts_valid_labels(tmp_path):
    _corpus(tmp_path)
    items = items_of(json.loads((tmp_path / "real.json").read_text(encoding="utf-8")))
    g = tally(items, {"items": GOOD})
    assert g["counts"] == {"FN": {"root only lacks a check": 1}, "FN_abstain": {"abstained: context overflow": 1},
                           "FP": {"ignored guard": 1}}
    assert (g["hand_coded"], g["mechanical"]) == (2, 1)


@pytest.mark.parametrize("edit, msg", [
    ({"rp-03/post": {"code": "missed sink", "note": "x"}}, "is not a FP code"),          # an FN code on an FP
    ({"rp-02/pre": {"code": "ignored guard", "note": "x"}}, "is not a FN code"),         # an FP code on an FN
    ({"rp-02/pre": {"code": "bad luck", "note": "x"}}, "is not a FN code"),
    ({"rp-03/pre": {"code": "other", "note": "x"}}, "coded mechanically"),
    ({"rp-02/pre": {"code": "missed sink", "note": " "}}, "one-line note"),
    ({"rp-09/pre": {"code": "other", "note": "x"}}, "extra"),
])
def test_tally_rejects_bad_labels(tmp_path, edit, msg):
    _corpus(tmp_path)
    items = items_of(json.loads((tmp_path / "real.json").read_text(encoding="utf-8")))
    with pytest.raises(GapError, match=msg):
        tally(items, {"items": {**GOOD, **edit}})
    with pytest.raises(GapError, match="missing"):
        tally(items, {"items": {k: v for k, v in GOOD.items() if k != "rp-02/pre"}})


# ---- command line -----------------------------------------------------------------------------

def _cli(*args):
    return subprocess.run([sys.executable, "-m", "taintwalk.eval.real_gap", *map(str, args)], cwd=REPO_ROOT,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)


def test_command_line_worksheet_then_tally(tmp_path):
    c = _corpus(tmp_path)
    out = tmp_path / "gap"
    r = _cli("worksheet", "--score", tmp_path / "real.json", "--manifest", tmp_path / "manifest.json",
             "--walk", c["walk"], "--programs", c["programs"], "--src", c["src"], "--out", out)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "GAP WORKSHEET OK: 3 items, 2 to hand-code, 1 mechanical" in r.stdout
    labels = json.loads((out / "labels.template.json").read_text(encoding="utf-8"))
    for k, v in GOOD.items():
        labels["items"][k] = v
    (out / "labels.json").write_text(json.dumps(labels), encoding="utf-8")
    r = _cli("tally", "--score", tmp_path / "real.json", "--labels", out / "labels.json", "--out", out)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "GAP TALLY OK: 3 items, 2 hand-coded, 1 mechanical" in r.stdout
    assert "| FP | ignored guard | 1 |" in (out / "gap.md").read_text(encoding="utf-8")
    shutil.copy(out / "labels.template.json", out / "labels.json")                 # unfilled: must fail
    r = _cli("tally", "--score", tmp_path / "real.json", "--labels", out / "labels.json", "--out", out)
    assert r.returncode == 1 and "GAP FAIL" in r.stdout