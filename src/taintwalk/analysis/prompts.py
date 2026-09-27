"""Prompt construction for the single-function taint summary (Phase 5; D-018, D-021).

build_prompt() is the only way analysis code turns pseudo-C into a prompt:
    redact_leaky_literals -> collapse_decompiler_noise -> strip blank edges -> number lines
    -> render -> assert_clean(system + "\\n" + user)
The provider pipeline gates the same text again before any cache or network I/O (D-019).
The returned `lines` are exactly the lines the model was shown, so evidence_issues()
checks evidence_line against the same numbering.

Design choices:
- Data flow first. The instructions define untrusted sources and dangerous operations and
  say that a scary call name is not a bug and a plain loop can be one. The schema puts the
  verdict last, so the model commits only after writing sources, sinks and flows.
- The vocabulary is described in words; no CWE id appears anywhere (D-021; the gate
  would reject it).
- Four hand-written few-shots, none taken from the corpus and none containing a string
  literal (D-021 forbids error-message literals; D-018 keeps them a Juliet shortcut risk,
  so the prompt must not teach "message => safe"). They cover: a dangerous loop with no
  dangerous call, a scary memcpy that is correctly bounded, an untrusted format string,
  and a guarded divisor whose tainted value is returned (returns_taint for Phase 6).
- The prompt holds nothing that varies between runs, so the cache key is stable.
"""
from __future__ import annotations

from dataclasses import dataclass

from taintwalk.analysis.sanitize import collapse_decompiler_noise, redact_leaky_literals
from taintwalk.analysis.summary_schema import TaintSummary
from taintwalk.util.leakcheck import assert_clean

PROMPT_VERSION = 1

_INSTRUCTIONS = """\
You analyze one function decompiled by Ghidra from a stripped x86-64 Linux executable and \
return a taint summary of it as JSON.

Reading the code:
- Names like FUN_00101a2b are functions whose names were stripped. Names like memcpy, fgets, \
recv, atoi or printf are real library imports and behave as documented.
- param_1, param_2, ... are the parameters. In the summary, parameters are indexed from 0: \
param_1 is index 0, param_2 is index 1.
- local_XX are local variables on the stack. DAT_XXXX are globals.
- A comment such as /* local_78[0..99] = 0: 100 stores collapsed */ stands for that many \
zero stores into the buffer, and tells you how large the buffer is.
- The string "<str>" is a literal that was removed. Lines are numbered on the left.

Untrusted data: function parameters (a caller may pass anything), and anything read from \
files, sockets, standard input, the environment or the command line, and values returned by \
random-number functions. Constants, and values computed only from constants, are trusted.

Method: follow each untrusted value through assignments, arithmetic, casts, pointer copies \
and calls. List every dangerous operation it reaches:
- an index or pointer offset used to read or write memory;
- the size or count given to a copy, or the bound of a copying loop;
- an allocation size;
- a divisor;
- arithmetic that can wrap, when its result matters;
- a format-string argument;
- a command string given to a shell.
An operation is guarded only when a check on the path constrains the untrusted value enough \
to make that operation safe, for example both bounds of an index. A check of one side only, \
or a check of a different variable, is not a guard. A dangerous-sounding call is not a flaw \
by itself, and a plain loop or a plain assignment can be one.

Fields, in the order you write them. The verdict comes last and must follow from what you \
listed before it.
- params: one entry per parameter, with its inferred type and its role: buffer, length, index, \
pointer, scalar, format, command or unknown.
- sources: each untrusted value. kind is param, input_call, global or call_return. ref names \
it: the parameter index as a string, or the called function's name.
- sinks: each dangerous operation an untrusted value reaches. sink_kind is call_arg (an \
argument of a call), array_index (an index or offset into memory), pointer_write (a write \
through a computed pointer), allocation_size, loop_bound, divisor or arithmetic. \
evidence_line is the number of \
the line where it happens. callee is the called function's name when the sink is a call \
argument, otherwise "". tainted_args lists the 0-based positions of the call arguments that \
carry untrusted data, or [] when the sink is not a call. guarded says whether a real guard \
protects it, and guard_expr quotes that check ("" when unguarded).
- propagation: edges from src to dst. An endpoint is source:N, sink:N or param:N (N is the \
position in that list, or the parameter index), or return. sanitized is true when the edge \
passes through a guard.
- returns_taint: true when the return value can carry untrusted data.
- callee_effects: one entry per unrecovered function (FUN_...) that is called, saying \
whether you believe its return value carries untrusted data.
- verdict: first a one-sentence reason, then mechanism, region, access, direction, then \
vulnerable and confidence.

Mechanism, the kind of flaw:
- out_of_bounds_access: a read or write outside the bounds of a buffer.
- integer_overflow: arithmetic on untrusted data that can wrap above the maximum of its type.
- integer_underflow: arithmetic on untrusted data that can wrap below the minimum of its type.
- overflowed_size_to_buffer: a size or count that can wrap and is then used to allocate or \
copy.
- divide_by_zero: an untrusted divisor that can be zero.
- untrusted_format_string: untrusted data used as a printf-family format string.
- os_command_injection: untrusted data that reaches a shell command.
- untrusted_loop_bound: an untrusted value that sets how many times a loop runs, with no \
upper limit.
- untrusted_allocation_size: an untrusted value used as an allocation size with no limit.
- other: a real memory-safety flaw that fits none of these.
- none: no dangerous operation is reachable by untrusted data without a real guard.
For out_of_bounds_access, region is stack (a local buffer), heap (memory from malloc, calloc, \
realloc or new), global (a DAT_ buffer) or unknown; access is read or write; direction is \
past_end or before_start. For every other mechanism, region, access and direction are all \
not_applicable.
vulnerable is true exactly when mechanism is not none. confidence is between 0 and 1.

The examples below show the method on made-up functions."""

# Hand-written examples. Not taken from the corpus; no string literals anywhere.
_EXAMPLES: list[tuple[str, str, dict]] = [
    (
        "FUN_00101a40",
        """\
void FUN_00101a40(char *param_1)
{
  long lVar1;
  char local_48 [56];

  lVar1 = 0;
  while (param_1[lVar1] != '\\0') {
    local_48[lVar1] = param_1[lVar1];
    lVar1 = lVar1 + 1;
  }
  local_48[lVar1] = '\\0';
  FUN_00101390(local_48);
  return;
}""",
        {
            "params": [{"index": 0, "inferred_type": "char *", "role": "buffer"}],
            "sources": [{"kind": "param", "ref": "0", "confidence": 0.9}],
            "sinks": [{
                "sink_kind": "array_index", "callee": "", "evidence_line": 8, "tainted_args": [],
                "guarded": False, "guard_expr": "", "confidence": 0.85,
            }],
            "propagation": [{"src": "source:0", "dst": "sink:0", "sanitized": False}],
            "returns_taint": False,
            "callee_effects": [{"callee": "FUN_00101390", "taints_return": False}],
            "verdict": {
                "reason": "the copy loop stops only at the end of the caller's string, so a "
                          "string longer than 55 characters is written past the end of local_48",
                "mechanism": "out_of_bounds_access", "region": "stack", "access": "write",
                "direction": "past_end", "vulnerable": True, "confidence": 0.85,
            },
        },
    ),
    (
        "FUN_00101b10",
        """\
void FUN_00101b10(void *param_1,ulong param_2)
{
  undefined1 local_118 [264];

  if (param_2 < 0x101) {
    memcpy(local_118,param_1,param_2);
    FUN_00101390(local_118);
  }
  return;
}""",
        {
            "params": [
                {"index": 0, "inferred_type": "void *", "role": "buffer"},
                {"index": 1, "inferred_type": "ulong", "role": "length"},
            ],
            "sources": [
                {"kind": "param", "ref": "0", "confidence": 0.9},
                {"kind": "param", "ref": "1", "confidence": 0.9},
            ],
            "sinks": [{
                "sink_kind": "call_arg", "callee": "memcpy", "evidence_line": 6, "tainted_args": [2],
                "guarded": True, "guard_expr": "param_2 < 0x101", "confidence": 0.9,
            }],
            "propagation": [{"src": "source:1", "dst": "sink:0", "sanitized": True}],
            "returns_taint": False,
            "callee_effects": [{"callee": "FUN_00101390", "taints_return": False}],
            "verdict": {
                "reason": "the copy size is checked to be at most 256 before memcpy into a "
                          "264-byte local buffer, so the copy stays in bounds",
                "mechanism": "none", "region": "not_applicable", "access": "not_applicable",
                "direction": "not_applicable", "vulnerable": False, "confidence": 0.85,
            },
        },
    ),
    (
        "FUN_00101c80",
        """\
void FUN_00101c80(void)
{
  char *pcVar1;
  char local_98 [136];

  pcVar1 = fgets(local_98,0x80,stdin);
  if (pcVar1 != (char *)0x0) {
    printf(local_98);
  }
  return;
}""",
        {
            "params": [],
            "sources": [{"kind": "input_call", "ref": "fgets", "confidence": 0.95}],
            "sinks": [{
                "sink_kind": "call_arg", "callee": "printf", "evidence_line": 8, "tainted_args": [0],
                "guarded": False, "guard_expr": "", "confidence": 0.9,
            }],
            "propagation": [{"src": "source:0", "dst": "sink:0", "sanitized": False}],
            "returns_taint": False,
            "callee_effects": [],
            "verdict": {
                "reason": "text read from standard input is passed to printf as the format "
                          "string; the fgets call itself is bounded by the buffer size",
                "mechanism": "untrusted_format_string", "region": "not_applicable",
                "access": "not_applicable", "direction": "not_applicable",
                "vulnerable": True, "confidence": 0.9,
            },
        },
    ),
    (
        "FUN_00101d20",
        """\
int FUN_00101d20(void)
{
  int iVar1;
  char local_28 [24];

  iVar1 = 0;
  if (fgets(local_28,0x10,stdin) != (char *)0x0) {
    iVar1 = atoi(local_28);
  }
  if (iVar1 == 0) {
    iVar1 = 1;
  }
  return 1000 / iVar1;
}""",
        {
            "params": [],
            "sources": [{"kind": "input_call", "ref": "fgets", "confidence": 0.9}],
            "sinks": [{
                "sink_kind": "divisor", "callee": "", "evidence_line": 13, "tainted_args": [],
                "guarded": True, "guard_expr": "if (iVar1 == 0) iVar1 = 1", "confidence": 0.85,
            }],
            "propagation": [
                {"src": "source:0", "dst": "sink:0", "sanitized": True},
                {"src": "source:0", "dst": "return", "sanitized": False},
            ],
            "returns_taint": True,
            "callee_effects": [],
            "verdict": {
                "reason": "the value read from standard input reaches the divisor only after a "
                          "zero is replaced by 1; the result depends on it and is returned, so "
                          "callers must treat the return value as untrusted",
                "mechanism": "none", "region": "not_applicable", "access": "not_applicable",
                "direction": "not_applicable", "vulnerable": False, "confidence": 0.8,
            },
        },
    ),
]


@dataclass(frozen=True)
class Prompt:
    system: str
    user: str
    lines: tuple[str, ...]   # exactly the code lines shown, line i+1 == lines[i]
    redactions: int
    collapsed: int


def prepare_code(pseudo_c: str) -> tuple[tuple[str, ...], int, int]:
    """Redact leaky literals, collapse zero-fill noise, strip blank edge lines."""
    if not isinstance(pseudo_c, str) or not pseudo_c.strip():
        raise ValueError("pseudo_c is empty; the function has nothing to analyze")
    text, redactions = redact_leaky_literals(pseudo_c)
    text, collapsed = collapse_decompiler_noise(text)
    lines = text.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return tuple(ln.rstrip() for ln in lines), redactions, collapsed


def render_user(function_name: str, lines: tuple[str, ...]) -> str:
    numbered = "\n".join(f"{i:4d}  {ln}" for i, ln in enumerate(lines, 1))
    return (f"Function {function_name}. Lines are numbered; evidence_line refers to these "
            f"numbers.\n\n{numbered}\n")


def _render_examples() -> str:
    parts = []
    for k, (name, code, summary) in enumerate(_EXAMPLES, 1):
        lines, _, _ = prepare_code(code)
        out = TaintSummary.model_validate(summary).model_dump_json()
        parts.append(f"Example {k}\nInput:\n{render_user(name, lines)}\nOutput:\n{out}")
    return "\n\n".join(parts)


SYSTEM = _INSTRUCTIONS + "\n\n" + _render_examples() + "\n"


def examples() -> list[tuple[str, tuple[str, ...], TaintSummary]]:
    """(name, shown lines, validated summary) for each few-shot. Used by tests."""
    return [(n, prepare_code(c)[0], TaintSummary.model_validate(s)) for n, c, s in _EXAMPLES]


def build_prompt(function_name: str, pseudo_c: str, *, binary_sha256: str | None) -> Prompt:
    """The only prompt builder. binary_sha256 is required, as in llm/base.py: pass the
    stripped binary's sha for the full gate, or None explicitly for static-only."""
    lines, redactions, collapsed = prepare_code(pseudo_c)
    user = render_user(function_name, lines)
    assert_clean(SYSTEM + "\n" + user, binary_sha256=binary_sha256)
    return Prompt(system=SYSTEM, user=user, lines=lines, redactions=redactions, collapsed=collapsed)