"""Callee-context rendering and build_prompt(callee_context=) (Phase 6, D-026)."""
from __future__ import annotations

import functools
import hashlib
import json

import pytest

from taintwalk.analysis.prompts import (
    CALLEE_HEADER,
    MODEL_TEXT_MAX,
    SYSTEM,
    CalleeView,
    build_prompt,
    prepare_code,
    render_callee_context,
    render_user,
)
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.util.leakcheck import LeakError, assert_clean

PREFLIGHT_BUDGET_CHARS = 28544   # (num_ctx 16384 - num_predict 2048 - 64) * 2.0 chars/token (D-019)
ROLES = ["buffer", "length", "index", "pointer", "scalar", "format", "command", "unknown"]
SOURCE_KINDS = ["param", "input_call", "global", "call_return"]
SINK_KINDS = ["call_arg", "array_index", "pointer_write", "allocation_size", "loop_bound",
              "divisor", "arithmetic"]
MECHANISMS = ["none", "out_of_bounds_access", "integer_overflow", "integer_underflow",
              "overflowed_size_to_buffer", "divide_by_zero", "untrusted_format_string",
              "os_command_injection", "untrusted_loop_bound", "untrusted_allocation_size", "other"]
OOB = [("stack", "write", "past_end"), ("heap", "read", "before_start"),
       ("global", "write", "before_start"), ("unknown", "read", "past_end")]
BIG = 10**6
CALLER = "void FUN_00101000(void)\n{\n  FUN_00102000(1);\n  return;\n}\n"


def summary(mechanism="none", *, where=("not_applicable",) * 3, params=(), sources=(), sinks=(),
            propagation=(), returns_taint=False, reason="r", conf=0.5):
    region, access, direction = where
    return {
        "params": list(params), "sources": list(sources), "sinks": list(sinks),
        "propagation": list(propagation), "returns_taint": returns_taint, "callee_effects": [],
        "verdict": {"reason": reason, "mechanism": mechanism, "region": region, "access": access,
                    "direction": direction, "vulnerable": mechanism != "none", "confidence": conf},
    }


def sink(kind="call_arg", callee="", *, guarded=False, guard_expr="", conf=0.5):
    return {"sink_kind": kind, "callee": callee, "evidence_line": 1, "tainted_args": [],
            "guarded": guarded, "guard_expr": guard_expr, "confidence": conf}


def param(i, role="buffer", t="char *"):
    return {"index": i, "inferred_type": t, "role": role}


def ok(addr, name, s):
    return CalleeView(addr=addr, name=name, status="ok", summary=s)


def effectful():
    return summary("out_of_bounds_access", where=("stack", "write", "past_end"),
                   params=[param(0)], sinks=[sink("call_arg", "strcpy")],
                   propagation=[{"src": "param:0", "dst": "sink:0", "sanitized": False}])


@functools.lru_cache(maxsize=1)
def programs():
    d = REPO_ROOT / load_config()["extract"]["out_dir"] / "programs"
    files = sorted(d.glob("*.json"))
    assert len(files) == 240, f"expected 240 program.json files in {d}; run the Phase 2 extract"
    return tuple(json.loads(f.read_text(encoding="utf-8")) for f in files)


@pytest.mark.corpus
def test_empty_context_is_byte_identical_to_the_phase5_prompts():
    run = REPO_ROOT / "runs" / "p5-gate"
    rows = sorted((run / "summaries").glob("*.json"))
    assert len(rows) == 20, "needs runs/p5-gate from the Phase 5 gate"
    progs = {p["binary"]["sha256"]: p for p in programs()}
    for fp in rows:
        row = json.loads(fp.read_text(encoding="utf-8"))
        fn = next(f for f in progs[row["binary_sha256"]]["functions"] if f["addr"] == row["address"])
        saved = json.loads((run / "prompts" / fp.name).read_text(encoding="utf-8"))
        p = build_prompt(fn["ghidra_name"], fn["pseudo_c"], binary_sha256=row["binary_sha256"])
        assert p.user == saved["user"], fp.name
        assert hashlib.sha256(p.system.encode()).hexdigest() == saved["system_sha256"]
        assert build_prompt(fn["ghidra_name"], fn["pseudo_c"], binary_sha256=row["binary_sha256"],
                            callee_context="") == p


def test_context_follows_the_numbered_code_and_keeps_the_lines():
    base = build_prompt("FUN_00101000", CALLER, binary_sha256=None)
    ctx = render_callee_context(base.lines, [ok("0x2000", "FUN_00102000", effectful())], max_chars=BIG)
    p = build_prompt("FUN_00101000", CALLER, binary_sha256=None, callee_context=ctx.text)
    assert p.user == base.user + "\n" + ctx.text + "\n"
    assert p.lines == base.lines and p.system == base.system
    assert ctx.text.startswith(CALLEE_HEADER)
    assert "FUN_00102000, called on line 3\n" in ctx.text


def test_a_leak_in_a_rendered_model_field_is_caught():
    s = effectful()
    s["sinks"][0].update(guarded=True, guard_expr="CWE-121 check")
    ctx = render_callee_context(("  FUN_00102000(1);",), [ok("0x2000", "FUN_00102000", s)], max_chars=BIG)
    assert "CWE-121 check" in ctx.text
    with pytest.raises(LeakError):
        build_prompt("FUN_00101000", CALLER, binary_sha256=None, callee_context=ctx.text)


def test_callees_are_ordered_by_first_call_line_with_their_lines():
    lines = ("int FUN_1(void)", "{", "  FUN_0010b(1);", "  x = 2;", "  FUN_0010a(2);", "  y = 3;",
             "  FUN_0010a(3);", "}")
    views = [ok("0xa", "FUN_0010a", effectful()), ok("0xb", "FUN_0010b", effectful()),
             ok("0xc", "FUN_0010c", effectful())]
    ctx = render_callee_context(lines, views, max_chars=BIG)
    assert ctx.order == ("0xb", "0xa", "0xc") and ctx.omitted == ()
    assert "FUN_0010b, called on line 3\n" in ctx.text
    assert "FUN_0010a, called on lines 5, 7\n" in ctx.text
    assert "\nFUN_0010c\n" in ctx.text


def test_reason_and_confidences_are_never_rendered():
    s = effectful()
    s["verdict"].update(reason="ZZREASONZZ", confidence=0.123)
    s["sinks"][0]["confidence"] = 0.456
    text = render_callee_context(("FUN_x();",), [ok("0x1", "FUN_x", s)], max_chars=BIG).text
    assert "ZZREASONZZ" not in text and "0.123" not in text and "0.456" not in text
    assert "  verdict: vulnerable, out_of_bounds_access stack/write/past_end" in text


def test_flows_name_their_sources_and_no_effect_callees_take_one_line():
    s = summary("untrusted_format_string", params=[param(0, "format")],
                sources=[{"kind": "input_call", "ref": "fgets", "confidence": 0.9}],
                sinks=[sink("call_arg", "printf")],
                propagation=[{"src": "source:0", "dst": "sink:0", "sanitized": False},
                             {"src": "param:0", "dst": "return", "sanitized": True}],
                returns_taint=True)
    text = render_callee_context(("FUN_a();", "FUN_b();"),
                                 [ok("0x1", "FUN_a", s), ok("0x2", "FUN_b", summary())], max_chars=BIG).text
    assert "  flows: input_call fgets -> sink:0; param:0 -> return (sanitized)" in text
    assert "  sinks: sink:0 call_arg printf, unguarded" in text
    assert "  returns taint: yes" in text
    assert "  verdict: vulnerable, untrusted_format_string\n" in text
    assert text.endswith("\nFUN_b, called on line 2: no taint effects (no sinks, no flows, returns no taint)")


def test_stub_lines():
    lines = ("FUN_a();", "FUN_b();", "FUN_c();", "FUN_d();")
    views = [CalleeView("0x1", "FUN_a", "recursive_pending"), CalleeView("0x2", "FUN_b", "out_of_scope"),
             CalleeView("0x3", "FUN_c", "decompile_failed"),
             CalleeView("0x4", "FUN_d", "failed", failure="max_tokens")]
    text = render_callee_context(lines, views, max_chars=BIG).text
    assert text.split("\n")[1:] == [
        "FUN_a, called on line 1: not yet available (recursive call); assume no taint effects",
        "FUN_b, called on line 2: no summary (outside analysis scope)",
        "FUN_c, called on line 3: no summary (decompilation failed)",
        "FUN_d, called on line 4: no summary (analysis failed: max_tokens)",
    ]


def test_model_text_is_flattened_and_capped():
    s = effectful()
    s["params"][0]["inferred_type"] = "x" * 500
    s["sinks"][0].update(guarded=True, guard_expr="a <\n   10\n\nINJECTED LINE")
    text = render_callee_context(("FUN_a();",), [ok("0x1", "FUN_a", s)], max_chars=BIG).text
    assert "guarded: a < 10 INJECTED LINE" in text
    assert "x" * MODEL_TEXT_MAX not in text and "..." in text
    assert len(text.split("\n")) == 1 + 6          # header + name line + 5 field lines


def test_budget_drops_the_last_called_callee_first():
    lines = ("FUN_a();", "FUN_b();", "FUN_c();")
    views = [ok(f"0x{i}", f"FUN_{c}", effectful()) for i, c in enumerate("abc", 1)]
    full = render_callee_context(lines, views, max_chars=BIG)
    cut = render_callee_context(lines, views, max_chars=len(full.text) - 1)
    assert cut.order == ("0x1", "0x2") and cut.omitted == ("0x3",)
    assert cut.text.endswith("\n1 callee summary omitted (budget)")
    assert len(cut.text) <= len(full.text) - 1
    assert render_callee_context(lines, views, max_chars=len(full.text) - 1) == cut
    with pytest.raises(ValueError, match="cannot hold"):
        render_callee_context(lines, views, max_chars=len(CALLEE_HEADER))


def test_invalid_views_are_rejected():
    with pytest.raises(ValueError):
        CalleeView("0x1", "FUN_a", "maybe")
    with pytest.raises(ValueError):
        CalleeView("0x1", "FUN_a", "ok")
    with pytest.raises(ValueError):
        CalleeView("0x1", "FUN_a", "failed", summary=summary())
    with pytest.raises(ValueError, match="duplicate"):
        render_callee_context(("x",), [CalleeView("0x1", "FUN_a", "out_of_scope"),
                                       CalleeView("0x1", "FUN_b", "out_of_scope")], max_chars=BIG)


def _maximal_summaries():
    params = [param(i, r, "int") for i, r in enumerate(ROLES)]
    sources = [{"kind": k, "ref": "0" if k == "param" else "fgets", "confidence": 0.5} for k in SOURCE_KINDS]
    sinks = [sink(k, "memcpy" if k == "call_arg" else "", guarded=i % 2 == 0,
                  guard_expr="n < 10" if i % 2 == 0 else "") for i, k in enumerate(SINK_KINDS)]
    prop = [{"src": "source:1", "dst": "sink:0", "sanitized": False},
            {"src": "param:2", "dst": "sink:1", "sanitized": True},
            {"src": "param:0", "dst": "return", "sanitized": False}]
    full = dict(params=params, sources=sources, sinks=sinks, propagation=prop, returns_taint=True)
    out = [summary(m, **full) for m in MECHANISMS if m != "out_of_bounds_access"]
    out += [summary("out_of_bounds_access", where=w, **full) for w in OOB]
    return out


@pytest.mark.corpus
def test_rendered_vocabulary_is_gate_clean_for_every_binary():
    maximal = _maximal_summaries()
    stubs = [("recursive_pending", ""), ("out_of_scope", ""), ("decompile_failed", ""), ("failed", "max_tokens")]
    for prog in programs():
        names = [f["ghidra_name"] for f in prog["functions"] if f["in_scope"]][:3]
        views = [ok(f"0x{i + 1:x}", names[i % len(names)], s) for i, s in enumerate(maximal)]
        views += [CalleeView(f"0x{100 + i:x}", names[i % len(names)], st, failure=fl)
                  for i, (st, fl) in enumerate(stubs)]
        ctx = render_callee_context(tuple(f"  {n}(1);" for n in names), views, max_chars=BIG)
        assert len(ctx.order) == len(views)
        assert_clean(ctx.text, binary_sha256=prog["binary"]["sha256"])


@pytest.mark.corpus
def test_callee_budget_fits_the_preflight_budget_for_every_function():
    cap = load_config()["walk"]["callee_context_max_chars"]
    worst, n = 0, 0
    for prog in programs():
        for f in prog["functions"]:
            if f["in_scope"] and f["pseudo_c"]:
                user = render_user(f["ghidra_name"], prepare_code(f["pseudo_c"])[0])
                worst = max(worst, len(SYSTEM) + 1 + len(user) + 1 + cap + 1)
                n += 1
    assert n == 11029
    assert worst <= PREFLIGHT_BUDGET_CHARS, f"worst prompt {worst} chars > {PREFLIGHT_BUDGET_CHARS}"