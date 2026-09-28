"""Prompt builder (Phase 5, analysis/prompts.py; D-018, D-021).

Few-shots: schema-valid, their evidence lines are right, they satisfy D-021's content
rules, and they carry no string literal. The system text describes every enum value and
passes the leak gate against every binary's name layer. build_prompt() succeeds, and is
deterministic, on every in-scope function in the corpus. Corpus tests fail, not skip,
when runs/p2-extract/programs is absent (same policy as test_tamper.py)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

from taintwalk.analysis.prompts import SYSTEM, build_prompt, examples, prepare_code, render_user
from taintwalk.analysis.sanitize import C_STRING, is_zero_store
from taintwalk.analysis.summary_schema import (
    Access,
    Direction,
    Mechanism,
    ParamRole,
    Region,
    SinkKind,
    SourceKind,
    evidence_issues,
)
from taintwalk.util.leakcheck import assert_clean

REPO = Path(__file__).resolve().parents[1]
PROGRAMS = REPO / "runs/p2-extract/programs"
DANGEROUS_IMPORTS = {"memcpy", "strcpy", "strcat", "sprintf", "gets", "memmove", "strncpy"}


def _programs():
    progs = sorted(PROGRAMS.glob("tw-*.json"))
    assert progs, f"no programs in {PROGRAMS}; run `taintwalk extract --all --report` first"
    return [json.loads(p.read_text()) for p in progs]


# ---- few-shots --------------------------------------------------------------------------

def test_fewshot_evidence_lines_are_right():
    for name, lines, s in examples():
        assert evidence_issues(s, list(lines), name) == [], name


def test_fewshots_meet_d021_content_rules():
    ex = examples()
    assert len(ex) >= 4
    verdicts = [s.verdict.vulnerable for _, _, s in ex]
    assert any(verdicts) and not all(verdicts)
    # safe but scary: not vulnerable, yet a dangerous import is a sink
    assert any(not s.verdict.vulnerable and any(k.callee in DANGEROUS_IMPORTS for k in s.sinks)
               for _, _, s in ex)
    # dangerous but bland: vulnerable, and no sink is a call at all
    assert any(s.verdict.vulnerable and all(k.callee == "" for k in s.sinks) for _, _, s in ex)
    # at least one example shows taint escaping through the return value (Phase 6 needs it)
    assert any(s.returns_taint for _, _, s in ex)


def test_fewshots_have_no_string_literals():
    # D-021: no error-message literal; stricter here: no literal of any kind.
    for name, lines, _ in examples():
        assert not C_STRING.search("\n".join(lines)), name


# ---- system text ------------------------------------------------------------------------

def test_system_describes_every_enum_value():
    for lit in (Mechanism, Region, Access, Direction, SinkKind, SourceKind, ParamRole):
        for v in get_args(lit):
            assert v in SYSTEM, f"{v} is never described in the instructions"


def test_system_passes_the_gate_for_every_binary():
    assert_clean(SYSTEM, binary_sha256=None)
    shas = {p["binary"]["sha256"] for p in _programs()}
    assert len(shas) == 240
    for sha in sorted(shas):
        assert_clean(SYSTEM, binary_sha256=sha)


# ---- builder ----------------------------------------------------------------------------

def test_numbering_and_blank_edges():
    lines, _, _ = prepare_code("\n\nvoid FUN_1(void)\n{\n  return;\n}\n\n")
    assert lines == ("void FUN_1(void)", "{", "  return;", "}")
    user = render_user("FUN_1", lines)
    assert "   1  void FUN_1(void)" in user and "   4  }" in user


def test_build_prompt_on_a_corpus_sample():
    # Every 10th binary (24 of 240), plus tw-0187, which holds the largest scored function
    # (pseudo-C survey). Gating all 11,029 prompts took ~50 s; gating every in-scope prompt
    # input is `taintwalk selftest --leak`'s job, not a unit test's.
    progs = _programs()
    largest = [p for p in progs if p["binary"]["path"].endswith("/tw-0187.stripped.elf")]
    assert len(largest) == 1
    sample = progs[::10] + largest
    n = redactions = collapsed = 0
    biggest = 0
    for prog in sample:
        sha = prog["binary"]["sha256"]
        for fn in prog["functions"]:
            if not fn["in_scope"]:
                continue
            p = build_prompt(fn["ghidra_name"], fn["pseudo_c"], binary_sha256=sha)  # gate inside
            assert p.system == SYSTEM
            assert not any(is_zero_store(a) and is_zero_store(b) and is_zero_store(c) and is_zero_store(d)
                           for a, b, c, d in zip(p.lines, p.lines[1:], p.lines[2:], p.lines[3:]))
            n += 1
            redactions += p.redactions
            collapsed += p.collapsed
            biggest = max(biggest, len(p.system) + len(p.user))
    print(f"\nprompts: {n} built from {len(sample)} binaries, {redactions} literals redacted, "
          f"{collapsed} store lines collapsed, system {len(SYSTEM)} chars, largest prompt {biggest} chars")
    assert n > 1000
    assert biggest <= 28544  # ollama preflight budget at num_ctx 16384 / num_predict 2048


def test_build_prompt_is_deterministic():
    prog = _programs()[0]
    fn = next(f for f in prog["functions"] if f["in_scope"])
    a = build_prompt(fn["ghidra_name"], fn["pseudo_c"], binary_sha256=prog["binary"]["sha256"])
    b = build_prompt(fn["ghidra_name"], fn["pseudo_c"], binary_sha256=prog["binary"]["sha256"])
    assert a == b