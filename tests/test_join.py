"""Label join (I4): synthetic programs exercising every match and miss reason."""
from __future__ import annotations

import pytest

from taintwalk.eval.join import JoinError, join_program

BASE = 0x100000


def _entry(funcs):
    return {"case_id": "tw-9999", "cwe": "CWE-121", "flow_variant": "01",
            "functions": [{"name": n, "addr": a, "addr_hex": hex(a), "size": s,
                           "label": l, "role": None, "cu": "x.c"} for n, a, s, l in funcs]}


def _prog(funcs):
    return {"binary": {"image_base": hex(BASE), "sha256": "0" * 64},
            "functions": [{"addr": hex(a), "size": s, "in_scope": ins, "excluded_reason": r}
                          for a, s, ins, r in funcs]}


def test_exact_match_and_scope_flags():
    e = _entry([("f_bad", 0x1000, 0x40, "bad"), ("f_good", 0x1100, 0x40, "good"),
                ("printLine", 0x1200, 0x20, "support"), ("main", 0x1300, 0x30, "harness")])
    p = _prog([(0x1000, 0x40, True, None), (0x1100, 0x40, True, None),
               (0x1200, 0x20, True, None), (0x1300, 0x30, True, None)])
    s = join_program(p, e)["stats"]
    assert (s["matched_testcase"], s["present_testcase"]) == (3, 3)
    assert (s["scored_bad"], s["scored_good"]) == (1, 1)
    assert (s["excluded_support"], s["excluded_harness"]) == (1, 1)
    assert s["base_offset"] == 0 and s["size_mismatch"] == 0


def test_base_offset_regression_is_detected():
    e = _entry([("f_bad", 0x1000, 0x40, "bad")])
    p = _prog([(0x1000 + BASE, 0x40, True, None)])          # un-normalized Ghidra address
    r = join_program(p, e)
    assert r["unmatched_in_scope"][0]["reason"] == "base_offset"
    assert r["unrecovered"][0]["reason"] == "base_offset"
    assert r["stats"]["base_offset"] == 2


def test_split_function_is_named():
    e = _entry([("f_good", 0x1100, 0x80, "good")])
    p = _prog([(0x1100, 0x40, True, None), (0x1140, 0x40, True, None)])
    r = join_program(p, e)
    assert r["unmatched_in_scope"][0]["reason"].startswith("split")


def test_merged_function_is_named():
    e = _entry([("f_bad", 0x1000, 0x40, "bad"), ("f_good", 0x1040, 0x40, "good")])
    p = _prog([(0x1000, 0x80, True, None)])
    r = join_program(p, e)
    assert r["unrecovered"][0]["reason"] == "merged:into 0x1000"


def test_extractor_exclusion_is_named():
    e = _entry([("f_bad", 0x1000, 0x40, "bad")])
    p = _prog([(0x1000, 0x40, False, "thunk")])
    assert join_program(p, e)["unrecovered"][0]["reason"] == "excluded_by_extractor:thunk"


def test_crt_in_scope_is_flagged():
    e = _entry([("frame_dummy", 0x1000, 0x10, "crt")])
    p = _prog([(0x1000, 0x10, True, None)])
    assert join_program(p, e)["stats"]["crt_in_scope"] == 1


def test_manifest_addr_disagreement_raises():
    e = _entry([("f_bad", 0x1000, 0x40, "bad")])
    e["functions"][0]["addr_hex"] = "0x1004"
    with pytest.raises(JoinError):
        join_program(_prog([(0x1000, 0x40, True, None)]), e)