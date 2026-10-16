"""Phase 10 agent loop (D-042): the R4 floor, every cap, refusals, the leak canary, replay.

Synthetic functions are built under a REAL corpus sha256, the pattern tests/test_walker.py uses:
analyze_function always passes the program's own sha to the leak gate, and D-017 makes an unknown
sha a LeakCheckConfigError, so a fake sha would disarm the gate instead of exercising it.
"""
import json
import pathlib

import pytest
from llm_fakes import FakeProvider, ok_response
from corpus_data import corpus_sha

from taintwalk.analysis.agent import (
    Caps, LLMPolicy, ScriptedPolicy, build_evidence, run_agent,
)
from taintwalk.analysis.analyze_one import analyze_function, stem
from taintwalk.config import load_config
from taintwalk.util.leakcheck import LeakError

SHA = corpus_sha("tw-0015")  # committed manifest: same value, needs no runs/ data (D-043)

CAPS = Caps(max_actions=8, max_calls=20, max_tokens_per_root=150000,
            read_code_max_chars=4000, evidence_max_chars=12000, token_chars_ratio=2.0)


def summ(vulnerable=False, guard=""):
    return {"params": [], "sources": [], "sinks": [
                {"sink_kind": "call_arg", "callee": "", "evidence_line": 1, "tainted_args": [],
                 "guarded": bool(guard), "guard_expr": guard, "confidence": 0.5}],
            "propagation": [], "returns_taint": False, "callee_effects": [],
            "verdict": {"reason": "r", "mechanism": "out_of_bounds_access" if vulnerable else "none",
                        "region": "stack" if vulnerable else "not_applicable",
                        "access": "write" if vulnerable else "not_applicable",
                        "direction": "past_end" if vulnerable else "not_applicable",
                        "vulnerable": vulnerable, "confidence": 0.6}}


def action(act, target="", reason="because"):
    return json.dumps({"reason": reason, "action": act, "target": target})


def _fn(addr, callees=(), *, body="void f(int param_1)\n{\n  return;\n}", failed=False):
    return {"addr": addr, "ghidra_name": f"FUN_{addr[2:]}", "in_scope": True,
            "decompile_failed": failed, "pseudo_c": None if failed else body,
            "callees": [{"kind": "internal", "addr": c, "name": None, "via_thunk": None}
                        for c in callees]}


def prog(*, dead=False):
    """Root 0x1000 calls 0x1100 and 0x1200; with dead=True it also calls 0x1300, which has no code."""
    callees = ("0x1100", "0x1200") + (("0x1300",) if dead else ())
    fns = [_fn("0x1000", callees), _fn("0x1100"), _fn("0x1200")]
    if dead:
        fns.append(_fn("0x1300", failed=True))
    return {"binary": {"sha256": SHA, "image_base": "0x100000"}, "functions": fns}


def scripted(responses):
    return FakeProvider(responses, cache=None)


def test_zero_step_judge_prompt_is_the_r4_prompt(tmp_path):
    """The floor: an agent that gathers nothing must reproduce R4's prompt byte for byte."""
    p = prog()
    agent_dir, base_dir = tmp_path / "agent", tmp_path / "base"

    prov = scripted([ok_response(text=action("finish")), ok_response(text=json.dumps(summ()))])
    row = run_agent(prov, p, "0x1000", agent_dir, policy=LLMPolicy(provider=prov), caps=CAPS)
    assert row["agent"]["stop"] == "finish" and row["agent"]["evidence_chars"] == 0

    analyze_function(scripted([ok_response(text=json.dumps(summ()))]), p, "0x1000", base_dir,
                     callee_context="")

    judged = json.loads((agent_dir / "prompts" / f"{stem(SHA, '0x1000')}.judge.json")
                        .read_text(encoding="utf-8"))["user"]
    r4 = json.loads((base_dir / "prompts" / f"{stem(SHA, '0x1000')}.json")
                    .read_text(encoding="utf-8"))["user"]
    assert judged == r4


def test_scripted_policy_reads_every_readable_callee_then_finishes(tmp_path):
    prov = scripted([ok_response(text=json.dumps(summ())) for _ in range(3)])
    row = run_agent(prov, prog(dead=True), "0x1000", tmp_path, policy=ScriptedPolicy(), caps=CAPS)
    a = row["agent"]
    assert a["summaries_fetched"] == ["0x1100", "0x1200"]      # 0x1300 has no code: never read
    assert a["stop"] == "finish" and a["steps"] == 3 and a["calls"] == 3
    assert a["evidence_chars"] > 0 and row["record"] is not None


def test_max_actions_stops_gathering(tmp_path):
    caps = Caps(1, 20, 150000, 4000, 12000, 2.0)
    prov = scripted([ok_response(text=json.dumps(summ())) for _ in range(2)])
    row = run_agent(prov, prog(), "0x1000", tmp_path, policy=ScriptedPolicy(), caps=caps)
    assert row["agent"]["stop"] == "max_actions" and row["agent"]["steps"] == 1
    assert row["record"] is not None


def test_token_budget_stops_gathering_and_blocks_the_judge(tmp_path):
    caps = Caps(8, 20, 1, 4000, 12000, 2.0)
    prov = scripted([ok_response(text=json.dumps(summ()))])
    row = run_agent(prov, prog(), "0x1000", tmp_path, policy=ScriptedPolicy(), caps=caps)
    assert row["agent"]["stop"] == "max_tokens"
    assert row["failure"] == "agent:budget" and row["record"] is None


def test_no_call_budget_for_the_judge_abstains(tmp_path):
    caps = Caps(8, 2, 150000, 4000, 12000, 2.0)
    prov = scripted([ok_response(text=action("read_summary", "0x1100")),
                     ok_response(text=json.dumps(summ()))])
    row = run_agent(prov, prog(), "0x1000", tmp_path, policy=LLMPolicy(provider=prov), caps=caps)
    assert row["failure"] == "agent:budget" and row["record"] is None
    assert not (tmp_path / "prompts" / f"{stem(SHA, '0x1000')}.judge.json").exists()


def test_invalid_target_is_refused_and_counted(tmp_path):
    prov = scripted([ok_response(text=action("read_code", "0x9999")),
                     ok_response(text=action("finish")),
                     ok_response(text=json.dumps(summ()))])
    row = run_agent(prov, prog(), "0x1000", tmp_path, policy=LLMPolicy(provider=prov), caps=CAPS)
    a = row["agent"]
    assert a["invalid_actions"] == 1 and a["stop"] == "finish" and a["code_read"] == []


def test_repeated_action_is_counted_not_re_executed(tmp_path):
    prov = scripted([ok_response(text=action("read_summary", "0x1100")),
                     ok_response(text=json.dumps(summ())),
                     ok_response(text=action("read_summary", "0x1100")),
                     ok_response(text=action("finish")),
                     ok_response(text=json.dumps(summ()))])
    row = run_agent(prov, prog(), "0x1000", tmp_path, policy=LLMPolicy(provider=prov), caps=CAPS)
    a = row["agent"]
    assert a["repeated_actions"] == 1 and a["summaries_fetched"] == ["0x1100"]


def test_leak_canary_in_a_summary_aborts(tmp_path):
    """A CWE id in a fetched summary must abort at the judge's build_prompt, not reach a model."""
    prov = scripted([ok_response(text=json.dumps(summ(guard="CWE-121 x"))),
                     ok_response(text=json.dumps(summ()))])
    with pytest.raises(LeakError):
        run_agent(prov, prog(), "0x1000", tmp_path, policy=ScriptedPolicy(), caps=CAPS)


def test_empty_evidence_is_empty_string():
    text, om = build_evidence(("  1  x",), [], [], max_chars=12000)
    assert text == "" and om == {"omitted_code_reads": 0, "omitted_summaries": 0}


def test_transcript_is_written_and_deterministic(tmp_path):
    out = []
    for name in ("a", "b"):
        d = tmp_path / name
        prov = scripted([ok_response(text=json.dumps(summ())) for _ in range(3)])
        run_agent(prov, prog(), "0x1000", d, policy=ScriptedPolicy(), caps=CAPS)
        out.append((d / "agent" / f"{stem(SHA, '0x1000')}.judge.json").read_bytes())
    assert out[0] == out[1]
    doc = json.loads(out[0])
    assert doc["stop"] == "finish" and len(doc["steps"]) == 3 and "wall_s" not in doc
