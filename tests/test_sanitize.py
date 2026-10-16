"""Decompiler-noise collapsing (Phase 5, analysis/sanitize.py). Synthetic cases prove the
rules; corpus cases prove that on all 11,029 in-scope functions the collapse removes only
zero-store lines and keeps every other line, in order. Corpus tests fail, not skip, when
runs/p2-extract/programs is absent (same policy as test_tamper.py)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from taintwalk.analysis.sanitize import (
    MIN_RUN,
    collapse_decompiler_noise,
    is_zero_store,
    redact_leaky_literals,
)

REPO = Path(__file__).resolve().parents[1]
PROGRAMS = REPO / "runs/p2-extract/programs"
EXPECT_IN_SCOPE = 11029
MARKER = re.compile(r"^\s*/\* .* = 0: \d+ stores collapsed \*/$")


def _body(stores: list[str]) -> str:
    return "\n".join(["void FUN_00101000(void)", "{", "  int x;", *stores, "  x = 1;", "}", ""])


# ---- rules ------------------------------------------------------------------------------

def test_long_index_run_becomes_one_marker_with_range_and_count():
    stores = [f"  local_78[{i}] = '\\0';" for i in range(100)]
    text, n = collapse_decompiler_noise(_body(stores))
    assert n == 100
    assert "  /* local_78[0..99] = 0: 100 stores collapsed */" in text.split("\n")
    assert "local_78[5]" not in text
    assert text.split("\n")[:3] == ["void FUN_00101000(void)", "{", "  int x;"]
    assert text.endswith("  x = 1;\n}\n")


def test_hex_indices_and_cast_stores():
    idx = [f"  local_48[0x{i:x}] = 0;" for i in range(10, 16)]
    cast = ["  *(undefined8 *)local_38 = 0;"] + [
        f"  *(undefined8 *)(local_38 + {8 * k}) = 0;" for k in range(1, 5)
    ]
    text, n = collapse_decompiler_noise(_body(idx + cast))
    assert n == 11
    assert "  /* local_48[10..15] = 0: 6 stores collapsed */" in text
    assert "  /* (local_38 + 0..32) = 0: 5 stores collapsed */" in text


def test_short_run_is_kept_verbatim():
    src = _body([f"  local_78[{i}] = '\\0';" for i in range(MIN_RUN - 1)])
    assert collapse_decompiler_noise(src) == (src, 0)


def test_different_buffers_are_separate_runs():
    a = [f"  local_78[{i}] = '\\0';" for i in range(4)]
    b = [f"  local_58[{i}] = '\\0';" for i in range(4)]
    text, n = collapse_decompiler_noise(_body(a + b))
    assert n == 8
    assert "local_78[0..3]" in text and "local_58[0..3]" in text


def test_nonzero_store_breaks_the_run_and_survives():
    stores = [f"  local_78[{i}] = '\\0';" for i in range(4)] + ["  local_78[4] = 'A';"] + [
        f"  local_78[{i}] = '\\0';" for i in range(5, 7)
    ]
    text, n = collapse_decompiler_noise(_body(stores))
    assert n == 4
    assert "  local_78[4] = 'A';" in text
    assert "  local_78[5] = '\\0';" in text  # the 2-line tail stays verbatim


def test_tainted_index_write_is_never_collapsed():
    stores = [f"  local_78[{i}] = '\\0';" for i in range(4)] + ["  local_78[iVar2] = '\\0';"]
    text, _ = collapse_decompiler_noise(_body(stores))
    assert "  local_78[iVar2] = '\\0';" in text
    assert not is_zero_store("  local_78[iVar2] = '\\0';")


def test_no_noise_is_byte_identical_and_collapse_is_idempotent():
    plain = _body(["  memcpy(local_78, param_1, 100);"])
    assert collapse_decompiler_noise(plain) == (plain, 0)
    once, _ = collapse_decompiler_noise(_body([f"  local_78[{i}] = '\\0';" for i in range(50)]))
    assert collapse_decompiler_noise(once) == (once, 0)


def test_collapse_does_not_touch_literal_redaction():
    src = 'printLine("Calling bad()...");\n' + "\n".join(f"local_78[{i}] = 0;" for i in range(8))
    red_first, k1 = redact_leaky_literals(src)
    coll, _ = collapse_decompiler_noise(src)
    red_after, k2 = redact_leaky_literals(coll)
    assert k1 == k2 == 1 and red_first.split("\n")[0] == red_after.split("\n")[0]


# ---- corpus -----------------------------------------------------------------------------

def _in_scope():
    progs = sorted(PROGRAMS.glob("tw-*.json"))
    assert progs, f"no programs in {PROGRAMS}; run `taintwalk extract --all --report` first"
    for p in progs:
        for fn in json.loads(p.read_text())["functions"]:
            if fn["in_scope"]:
                yield p.stem, fn


def _signal(lines: list[str]) -> list[str]:
    return [ln for ln in lines if not is_zero_store(ln) and not MARKER.match(ln)]


@pytest.mark.corpus
def test_corpus_collapse_removes_only_zero_stores():
    n_fn = n_touched = n_lines = c_before = c_after = 0
    for case, fn in _in_scope():
        before = fn["pseudo_c"]
        after, k = collapse_decompiler_noise(before)
        b, a = before.split("\n"), after.split("\n")
        where = f"{case} {fn['addr']}"
        assert _signal(b) == _signal(a), f"{where}: a non-noise line changed"
        assert sum(map(is_zero_store, b)) - sum(map(is_zero_store, a)) == k, where
        assert collapse_decompiler_noise(after) == (after, 0), f"{where}: not idempotent"
        n_fn += 1
        n_touched += k > 0
        n_lines += k
        c_before += len(before)
        c_after += len(after)
    print(f"\ncollapse: {n_fn} in-scope functions, {n_touched} touched, {n_lines} store lines "
          f"collapsed, chars {c_before} -> {c_after} ({100 * (c_before - c_after) / c_before:.1f}% less)")
    assert n_fn == EXPECT_IN_SCOPE


@pytest.mark.corpus
def test_worst_survey_case_collapses():
    fn = next(f for c, f in _in_scope() if c == "tw-0112" and f["addr"] == "0x193d")
    before = fn["pseudo_c"].split("\n")
    after, k = collapse_decompiler_noise(fn["pseudo_c"])
    print(f"\ntw-0112 0x193d: {len(before)} -> {len(after.split(chr(10)))} lines, {k} collapsed")
    assert k >= 100
    assert "100 stores collapsed" in after