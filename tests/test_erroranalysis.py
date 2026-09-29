"""Error-analysis tooling (Phase 8, D-032): seeded sample, worksheet, parroting, sanitizer-literal shortcut,
abstentions, and no provider module loaded."""
from __future__ import annotations

import copy
import json
import subprocess
import sys

from taintwalk.config import REPO_ROOT
from taintwalk.eval.baselines import llm_rung_doc
from taintwalk.eval.erroranalysis import (
    ERROR_SAMPLE_SEED,
    PARROT_MIN_WORDS,
    _words,
    abstention_kinds,
    arm_reasons,
    error_sample,
    fewshot_reasons,
    literal_shortcut,
    parroting,
    worksheet,
)
from taintwalk.eval.metrics import score_rung
from taintwalk.extract.report import load_manifest

P6 = REPO_ROOT / "runs" / "p6-gate"
LABELS = REPO_ROOT / "runs" / "p2-extract" / "labels"
PROGRAMS = REPO_ROOT / "runs" / "p2-extract" / "programs"


def _root(i, cell):
    return {"case_id": f"tw-{i:04d}", "addr": "0x1000", "cell": cell}


def test_error_sample_is_seeded_and_capped():
    score = {"roots": [_root(i, "FP") for i in range(30)] + [_root(100 + i, "FN") for i in range(5)]
             + [_root(200, "TP")]}
    a, b = error_sample(score), error_sample(score)
    assert len(a["FP"]) == 20 and len(a["FN"]) == 5 and a == b
    assert error_sample(score, seed=ERROR_SAMPLE_SEED + 1)["FP"] != a["FP"]


def test_parroting_flags_a_run_copied_from_a_few_shot_reason():
    words = _words(fewshot_reasons()[0])
    copied = " ".join(words[:PARROT_MIN_WORDS]) + " zzq qqz"
    near = " ".join(words[:PARROT_MIN_WORDS - 1]) + " zzq qqz"
    out = parroting([copied, near, "nothing here resembles any example at all"])
    assert out["answered"] == 3 and out["parroted"] == 1 and out["examples"] == [copied]


def test_literal_shortcut_counts_outcomes_by_label(tmp_path):
    progs = tmp_path / "programs"
    progs.mkdir()
    for case, code in (("tw-0001", 'if (9 < i) { printLine("ERROR: Array index is out-of-bounds"); }'),
                       ("tw-0002", "buf[i] = 0;")):
        (progs / f"{case}.json").write_text(json.dumps({"functions": [{"addr": "0x1000", "pseudo_c": code}]}),
                                            encoding="utf-8")
    score = {"roots": [{"case_id": "tw-0001", "addr": "0x1000", "label": "good", "outcome": "clear"},
                       {"case_id": "tw-0002", "addr": "0x1000", "label": "good", "outcome": "flagged"},
                       {"case_id": "tw-0002", "addr": "0x1000", "label": "bad", "outcome": "abstain"}]}
    out = literal_shortcut(score, progs)
    assert out["good"]["with_literal"] == {"n": 1, "flagged": 0, "clear": 1, "abstain": 0}
    assert out["good"]["without_literal"] == {"n": 1, "flagged": 1, "clear": 0, "abstain": 0}
    assert out["bad"]["with_literal"]["n"] == 0 and out["bad"]["without_literal"]["abstain"] == 1


def test_worksheet_shows_what_the_model_saw(tmp_path):
    """Corpus-dependent (fails, never skips). tw-0015's roots are forced into FP and FN to exercise the page."""
    score = score_rung(llm_rung_doc(P6, "R5"), manifest=load_manifest(), labels_dir=LABELS, programs_dir=PROGRAMS)
    forced = copy.deepcopy(score)
    for r in forced["roots"]:
        r["cell"] = "FN" if r["label"] == "bad" else "FP"
    md, index = worksheet(forced, P6, arm="walk", programs_dir=PROGRAMS)
    assert len(index["FP"]) == len(forced["roots"]) - 1 and len(index["FN"]) == 1
    assert "## Codebook" in md and "```c" in md and "- reason: " in md
    assert "Callee block the walk showed the model" in md


def test_abstentions_and_reasons_match_the_walk():
    walk = json.loads((P6 / "walk.json").read_text(encoding="utf-8"))
    failed = sum(f["status"] != "ok" for f in walk["functions"].values())
    assert sum(abstention_kinds(P6, "walk").values()) == failed
    assert len(arm_reasons(P6, "walk")) == len(walk["functions"]) - failed


def test_error_analysis_and_pipeline_load_no_provider_module():
    code = ("import sys, taintwalk.eval.erroranalysis, taintwalk.eval.pipeline; "
            "print(any(m == 'taintwalk.llm' or m.startswith('taintwalk.llm.') for m in sys.modules))")
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0 and proc.stdout.strip() == "False", proc.stderrs