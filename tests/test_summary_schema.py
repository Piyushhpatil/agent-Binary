"""TaintSummary v1 contract (D-021): shape, validators, gate-cleanliness, evidence checks,
and the Anthropic structured-output limits, checked offline through the SDK's own
transform_schema() (D-020). No network, no model."""
from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from anthropic import transform_schema
from pydantic import ValidationError

from taintwalk.analysis.summary_schema import (
    SCHEMA_VERSION,
    SummaryRecord,
    TaintSummary,
    evidence_issues,
)
from taintwalk.util.leakcheck import assert_clean

ANTHROPIC_MAX_OPTIONAL = 24
ANTHROPIC_MAX_UNION = 16

# Hand-written, not from the corpus.
VALID: dict[str, Any] = {
    "params": [],
    "sources": [{"kind": "input_call", "ref": "rand", "confidence": 0.9}],
    "sinks": [{
        "sink_kind": "array_index", "callee": "", "evidence_line": 4, "tainted_args": [],
        "guarded": False, "guard_expr": "", "confidence": 0.8,
    }],
    "propagation": [{"src": "source:0", "dst": "sink:0", "sanitized": False}],
    "returns_taint": False,
    "callee_effects": [],
    "verdict": {
        "reason": "index from rand() reaches a local array write; only the lower bound is checked",
        "mechanism": "out_of_bounds_access", "region": "stack", "access": "write",
        "direction": "past_end", "vulnerable": True, "confidence": 0.8,
    },
}

LINES = [
    "void FUN_00101000(void)",
    "{",
    "  int idx = rand();",
    "  buf[idx] = 1;",
    "  memcpy(dst, src, n);",
    "}",
]
SELF = "FUN_00101000"


def _mutate(path: list[Any], value: Any = None, delete: bool = False) -> dict[str, Any]:
    d = copy.deepcopy(VALID)
    node = d
    for k in path[:-1]:
        node = node[k]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return d


def _schemas(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _schemas(v)
    elif isinstance(node, list):
        for v in node:
            yield from _schemas(v)


def _count_optional(schema: dict[str, Any]) -> int:
    return sum(
        len(set(s["properties"]) - set(s.get("required", [])))
        for s in _schemas(schema)
        if isinstance(s.get("properties"), dict) and s.get("type") == "object"
    )


def _count_union(schema: dict[str, Any]) -> int:
    return sum(
        1 for s in _schemas(schema)
        if "anyOf" in s or "oneOf" in s or isinstance(s.get("type"), list)
    )


# ---- shape ------------------------------------------------------------------------------

def test_valid_summary_round_trips_and_wraps_in_a_record():
    s = TaintSummary.model_validate(VALID)
    assert s.model_dump() == VALID
    rec = SummaryRecord(schema_version=SCHEMA_VERSION, function=SELF, address="0x1000", summary=s)
    assert SummaryRecord.model_validate_json(rec.model_dump_json()) == rec


@pytest.mark.parametrize(
    "bad",
    [
        _mutate(["returns_taint"], delete=True),
        _mutate(["verdict", "mechanism"], "stack_buffer_overflow"),
        _mutate(["sinks", 0, "guarded"], "maybe"),
        _mutate(["sinks", 0, "address"], "0x401196"),
        _mutate(["propagation", 0, "dst"], "memcpy"),
        _mutate(["verdict", "vulnerable"], False),
        _mutate(["verdict"], {**VALID["verdict"], "mechanism": "none"}),
        _mutate(["sinks", 0, "confidence"], 1.5),
    ],
    ids=["missing-field", "bad-enum", "wrong-type", "extra-field", "bad-endpoint",
         "vulnerable-false-with-mechanism", "mechanism-none-but-vulnerable", "confidence-over-1"],
)
def test_invalid_summaries_are_rejected(bad):
    with pytest.raises(ValidationError):
        TaintSummary.model_validate(bad)


def test_evidence_first_verdict_last():
    s = TaintSummary.model_json_schema()
    assert list(s["properties"]) == [
        "params", "sources", "sinks", "propagation", "returns_taint", "callee_effects", "verdict",
    ]
    assert list(s["$defs"]["Verdict"]["properties"]) == [
        "reason", "mechanism", "region", "access", "direction", "vulnerable", "confidence",
    ]


# ---- D-021: no optionals, no unions, gate-clean vocabulary ------------------------------

def test_every_field_is_required_and_nothing_is_a_union():
    s = TaintSummary.model_json_schema()
    assert _count_optional(s) == 0
    assert _count_union(s) == 0


def test_schema_and_vocabulary_pass_the_leak_gate():
    # The schema itself is not gated (D-017), but summary values will be pasted into caller
    # prompts in Phase 6, and every enum value and field name lives in this text.
    assert_clean(json.dumps(TaintSummary.model_json_schema()), binary_sha256=None)


def test_anthropic_limits_after_transform_schema_offline():
    t = transform_schema(TaintSummary.model_json_schema())
    opt, uni = _count_optional(t), _count_union(t)
    print(f"\nanthropic transform_schema: optional={opt}/{ANTHROPIC_MAX_OPTIONAL} union={uni}/{ANTHROPIC_MAX_UNION}")
    assert opt <= ANTHROPIC_MAX_OPTIONAL and uni <= ANTHROPIC_MAX_UNION
    assert opt == 0 and uni == 0  # D-021 claims zero by construction


# ---- evidence checks (measured, not repaired) -------------------------------------------

def _with_sinks(*sinks: tuple[str, int]) -> TaintSummary:
    d = copy.deepcopy(VALID)
    d["sinks"] = [{**VALID["sinks"][0], "callee": c, "evidence_line": n} for c, n in sinks]
    return TaintSummary.model_validate(d)


def test_evidence_clean():
    assert evidence_issues(_with_sinks(("", 4), ("memcpy", 5)), LINES, SELF) == []


@pytest.mark.parametrize(
    "sink,issue",
    [
        (("", 99), "line_out_of_range"),
        (("strcpy", 5), "callee_not_on_line"),
        ((SELF, 1), "callee_is_self"),
    ],
)
def test_evidence_issues(sink, issue):
    assert evidence_issues(_with_sinks(sink), LINES, SELF) == [(0, issue)]