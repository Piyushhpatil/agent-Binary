"""Paired comparisons, Holm, ablation strata and the prompt byte-identity audit (Phase 8, D-030, D-034)."""
from __future__ import annotations

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.eval.ablation import (
    LOCAL_COMPARISONS,
    AblationError,
    ablation,
    audit_prompts,
    holm,
    mcnemar_exact,
    paired,
    preregistered_tests,
    single_insertion,
    stratum_of,
)

P6 = REPO_ROOT / "runs" / "p6-gate"


def _root(case, addr, label, cell, members=None):
    return {"case_id": case, "addr": addr, "label": label, "cell": cell,
            "binary_sha256": "s" * 64, "members": members or [addr]}


def test_mcnemar_exact_values():
    assert mcnemar_exact(7, 1) == pytest.approx(0.0703125)
    assert mcnemar_exact(1, 7) == pytest.approx(0.0703125)
    assert mcnemar_exact(10, 0) == pytest.approx(2 / 1024)
    assert mcnemar_exact(0, 0) == 1.0 and mcnemar_exact(3, 3) == 1.0


def test_holm_step_down():
    out = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert out["a"] == {"p": 0.01, "p_holm": 0.03, "reject": True}
    assert out["c"]["p_holm"] == 0.06 and out["b"]["p_holm"] == 0.06
    assert not out["b"]["reject"] and not out["c"]["reject"]


def test_paired_counts_discordant_roots_per_label():
    a = [_root("c1", "0x1", "bad", "TP"), _root("c2", "0x1", "bad", "TP"), _root("c3", "0x1", "bad", "FN_abstain"),
         _root("c1", "0x2", "good", "TN"), _root("c2", "0x2", "good", "FP")]
    b = [_root("c1", "0x1", "bad", "FN"), _root("c2", "0x1", "bad", "TP"), _root("c3", "0x1", "bad", "TP"),
         _root("c1", "0x2", "good", "TN"), _root("c2", "0x2", "good", "TN")]
    out = paired(a, b)
    assert out["bad"] == {"n": 3, "a_right": 2, "b_right": 2, "both": 1, "a_only": 1, "b_only": 1,
                          "neither": 0, "p": 1.0}
    assert (out["good"]["both"], out["good"]["a_only"], out["good"]["b_only"]) == (1, 0, 1)


def test_paired_fails_closed_when_the_roots_differ():
    with pytest.raises(AblationError, match="different roots"):
        paired([_root("c1", "0x1", "bad", "TP")], [_root("c1", "0x9", "bad", "TP")])
    with pytest.raises(AblationError, match="twice"):
        paired([_root("c1", "0x1", "bad", "TP")] * 2, [_root("c1", "0x1", "bad", "TP")])


def test_stratum_of():
    assert stratum_of(0, ["0x1"]) == "S0"
    assert stratum_of(40, ["0x1"]) == "S1"
    assert stratum_of(40, ["0x1", "0x2"]) == "S2"
    with pytest.raises(AblationError):
        stratum_of(0, ["0x1", "0x2"])


def test_ablation_per_stratum_and_the_s0_identity_rule():
    walk = [_root("c1", "0x1", "bad", "TP"), _root("c1", "0x2", "good", "FP"),
            _root("c2", "0x1", "bad", "TP", ["0x1", "0x5"])]
    base = [_root("c1", "0x1", "bad", "TP"), _root("c1", "0x2", "good", "TN"),
            _root("c2", "0x1", "bad", "FN", ["0x1", "0x5"])]
    strata = {("c1", "0x1"): "S0", ("c1", "0x2"): "S1", ("c2", "0x1"): "S2"}
    out = ablation(walk, base, strata)
    assert out["all"]["bad"]["a_only"] == 1 and out["all"]["good"]["b_only"] == 1
    assert out["S0"]["bad"]["both"] == 1 and out["S1"]["good"]["b_only"] == 1 and out["S2"]["bad"]["a_only"] == 1
    assert out["counts"] == {"S0": 1, "S1": 1, "S2": 1}
    base[0] = _root("c1", "0x1", "bad", "FN")
    with pytest.raises(AblationError, match="S0"):
        ablation(walk, base, strata)


def test_single_insertion():
    assert single_insertion("abcXYZ", "abc123XYZ") == 3
    assert single_insertion("abcXYZ", "abcXYZ123") == 3
    assert single_insertion("abcXYZ", "123abcXYZ") == 3
    assert single_insertion("abcXYZ", "abcXYZ") == 0
    assert single_insertion("aa", "aaa") == 1
    assert single_insertion("abcXYZ", "abc1XY2Z") is None
    assert single_insertion("abcXYZ", "abc") is None


def test_preregistered_family_is_ten_tests_and_holm_needs_all_of_them():
    roots = [_root("c1", "0x1", "bad", "TP"), _root("c1", "0x2", "good", "TN")]
    rungs = {r: roots for r in ("R2", "R3", "R4", "R5", "R6", "R7")}
    full = preregistered_tests(rungs)
    assert len(full["tests"]) == 10 and full["holm_applied"] and full["missing"] == []
    assert all("p_holm" in t for t in full["tests"].values())
    part = preregistered_tests({k: v for k, v in rungs.items() if k != "R6"})
    assert part["missing"] == ["C1"] and not part["holm_applied"] and len(part["tests"]) == 8
    assert not any("p_holm" in t for t in part["tests"].values())


def test_the_local_only_family_is_six_tests_with_holm():
    roots = [_root("c1", "0x1", "bad", "TP"), _root("c1", "0x2", "good", "TN")]
    out = preregistered_tests({r: roots for r in ("R2", "R3", "R4", "R5")}, comparisons=LOCAL_COMPARISONS)
    assert out["family"] == 6 and out["holm_applied"] and len(out["tests"]) == 6
    assert sorted({t["comparison"] for t in out["tests"].values()}) == ["C2", "C3L", "C4L"]


@pytest.mark.corpus
def test_prompt_audit_on_the_phase6_gate_walk():
    """Corpus-dependent (fails, never skips): 12 functions with a no-context prompt."""
    a = audit_prompts(P6)
    assert a["checked"] == 12 and a["failures"] == []
