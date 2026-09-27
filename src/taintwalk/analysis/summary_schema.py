"""TaintSummary v1: the per-function analysis contract (D-021; replaces the SPEC §8 shape).

The model fills TaintSummary. The code fills SummaryRecord's function and address.

Rules that shape this file:
- Id-free vocabulary. No value names a CWE id or carries a _bad/_good suffix, so a summary
  can be pasted into a caller's prompt (Phase 6) without tripping the leak gate. eval/ maps
  mechanism + region + access + direction to a CWE id in Phase 7; this module never
  imports that table.
- Every field is required and nothing is nullable. Absence is "", [] or "not_applicable".
  That keeps the schema at 0 optional and 0 union parameters (Anthropic caps them at 24
  and 16; nullable fields count as unions).
- Field order is evidence first, verdict last, and inside the verdict the reason comes
  before the commitment. Under constrained decoding the model writes in this order, so
  the verdict is conditioned on the evidence it has already written.
- Validators (propagation endpoint format; vulnerable <=> mechanism != "none") run
  client-side only. They never appear in the JSON schema sent to a provider. A failure
  triggers the single repair (D-019).
- evidence_issues() is measured per run, never repaired.
- The model classes have no docstrings on purpose: pydantic copies class docstrings into
  the JSON schema as descriptions, which would change the schema and the cache key.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1

Mechanism = Literal[
    "none",
    "out_of_bounds_access",
    "integer_overflow",
    "integer_underflow",
    "overflowed_size_to_buffer",
    "divide_by_zero",
    "untrusted_format_string",
    "os_command_injection",
    "untrusted_loop_bound",
    "untrusted_allocation_size",
    "other",
]
Region = Literal["stack", "heap", "global", "unknown", "not_applicable"]
Access = Literal["read", "write", "not_applicable"]
Direction = Literal["past_end", "before_start", "not_applicable"]
ParamRole = Literal["buffer", "length", "index", "pointer", "scalar", "format", "command", "unknown"]
SourceKind = Literal["param", "input_call", "global", "call_return"]
SinkKind = Literal[
    "call_arg", "array_index", "pointer_write", "allocation_size", "loop_bound", "divisor", "arithmetic",
]

ENDPOINT = re.compile(r"(?:param|source|sink):\d+|return")
Confidence = Annotated[float, Field(ge=0, le=1)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Param(_Strict):
    index: int = Field(ge=0)
    inferred_type: str
    role: ParamRole


class Source(_Strict):
    kind: SourceKind
    ref: str
    confidence: Confidence


class Sink(_Strict):
    sink_kind: SinkKind
    callee: str
    evidence_line: int = Field(ge=1)
    tainted_args: list[int]
    guarded: bool
    guard_expr: str
    confidence: Confidence


class Flow(_Strict):
    src: str
    dst: str
    sanitized: bool

    @field_validator("src", "dst")
    @classmethod
    def _endpoint(cls, v: str) -> str:
        if not ENDPOINT.fullmatch(v):
            raise ValueError("must be param:N, source:N, sink:N or return")
        return v


class CalleeEffect(_Strict):
    callee: str
    taints_return: bool


class Verdict(_Strict):
    reason: str
    mechanism: Mechanism
    region: Region
    access: Access
    direction: Direction
    vulnerable: bool
    confidence: Confidence

    @model_validator(mode="after")
    def _consistent(self) -> "Verdict":
        if self.vulnerable != (self.mechanism != "none"):
            raise ValueError("vulnerable must be true exactly when mechanism is not none")
        return self


class TaintSummary(_Strict):
    params: list[Param]
    sources: list[Source]
    sinks: list[Sink]
    propagation: list[Flow]
    returns_taint: bool
    callee_effects: list[CalleeEffect]
    verdict: Verdict


class SummaryRecord(_Strict):
    schema_version: Literal[1]
    function: str   # Ghidra name, filled by code
    address: str    # program.json addr (image base subtracted, D-016), filled by code
    summary: TaintSummary


def evidence_issues(summary: TaintSummary, lines: list[str], function_name: str) -> list[tuple[int, str]]:
    """Check each sink against the numbered lines the model was shown. Measured, not repaired.

    Returns (sink index, issue) pairs. Issues: line_out_of_range, callee_not_on_line,
    callee_is_self.
    """
    out: list[tuple[int, str]] = []
    for i, s in enumerate(summary.sinks):
        if not 1 <= s.evidence_line <= len(lines):
            out.append((i, "line_out_of_range"))
        elif s.callee and s.callee not in lines[s.evidence_line - 1]:
            out.append((i, "callee_not_on_line"))
        if s.callee and s.callee == function_name:
            out.append((i, "callee_is_self"))
    return out