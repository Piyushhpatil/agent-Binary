"""Phase 10 agent tools (D-042): label-free reads over one program.json for one root.

Every tool is scoped to the root's downward closure (D-036): the root and every in-scope function it
reaches. The root itself is never a read target, because the judge already shows its code.

- list_callees(scope, addr): the internal callees of one function in scope, by address, each with a
  status: "readable" (in scope, has pseudo-C), "no_code" (decompilation failed) or "out_of_scope" (an
  internal call into a function the extractor excluded).
- read_code(scope, addr, max_chars=...): the function's pseudo-C prepared exactly as the judge prepares
  code (analysis/prompts.prepare_code: literal redaction, zero-fill collapse), but unnumbered, so it can
  sit in the judge's evidence block without shifting evidence_line (the reason D-026 leaves the callee
  block unnumbered). Cut at whole lines, with a visible marker.
- read_summary(provider, scope, addr, run_dir): the function's no-context summary: analyze_function with
  no callee context, which is the R4 prompt exactly. Same prompt, same cache key, so on the Juliet corpus
  these are cache hits on the Phase 8 baseline rows.

A request outside the scope raises ToolError before any model call; the agent loop counts it as an
invalid action. finish is not a tool: it touches nothing, and the loop handles it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from taintwalk.analysis.analyze_one import analyze_function
from taintwalk.analysis.callgraph import CallGraph, addr_key, build_graph, downward_closure
from taintwalk.analysis.prompts import CalleeView, prepare_code
from taintwalk.llm.base import LLMProvider

CALLEE_STATUSES = ("readable", "no_code", "out_of_scope")
TRUNC_MARK = "[{n} more characters not shown]"


class ToolError(ValueError):
    """A tool request outside the root's scope. Raised before any model call."""


@dataclass(frozen=True)
class Scope:
    prog: dict[str, Any]
    graph: CallGraph
    root: str
    closure: frozenset[str]
    fns: dict[str, dict[str, Any]]


def make_scope(prog: dict[str, Any], root: str) -> Scope:
    """The tools' view of one root. Fails closed (ValueError) if the root is not an in-scope function."""
    graph = build_graph(prog)
    closure = downward_closure(graph, (root,))
    fns = {f["addr"]: f for f in prog["functions"]}
    return Scope(prog=prog, graph=graph, root=root, closure=closure, fns=fns)


def has_code(f: dict[str, Any]) -> bool:
    return f.get("pseudo_c") is not None and not f.get("decompile_failed")


def _name(scope: Scope, addr: str) -> str:
    return (scope.fns.get(addr) or {}).get("ghidra_name") or addr


def _target(scope: Scope, addr: str, *, allow_root: bool) -> dict[str, Any]:
    if addr not in scope.closure:
        raise ToolError(f"{addr} is not a function in this analysis scope")
    if addr == scope.root and not allow_root:
        raise ToolError(f"{addr} is the function under analysis; its code is already shown")
    return scope.fns[addr]


def list_callees(scope: Scope, addr: str) -> list[dict[str, str]]:
    """Internal callees of one in-scope function, by address. Imports are not listed: their names are
    already in the pseudo-C, and there is nothing to read behind them."""
    _target(scope, addr, allow_root=True)
    out = [{"addr": a, "name": _name(scope, a), "status": "readable" if has_code(scope.fns[a]) else "no_code"}
           for a in scope.graph.succ[addr]]
    out += [{"addr": a, "name": _name(scope, a), "status": "out_of_scope"} for a in scope.graph.stubs[addr]]
    return sorted(out, key=lambda c: addr_key(c["addr"]))


def read_code(scope: Scope, addr: str, *, max_chars: int) -> str:
    """Prepared, unnumbered pseudo-C of one function in scope, cut at whole lines at max_chars."""
    if max_chars < 1:
        raise ValueError("max_chars must be positive")
    f = _target(scope, addr, allow_root=False)
    if not has_code(f):
        raise ToolError(f"{addr} has no decompiled code")
    lines, _, _ = prepare_code(f["pseudo_c"])
    text = "\n".join(lines)
    if len(text) <= max_chars:
        return text
    kept: list[str] = []
    size = 0
    for ln in lines:
        add = len(ln) + (1 if kept else 0)
        if size + add > max_chars:
            break
        kept.append(ln)
        size += add
    shown = "\n".join(kept)
    return (shown + "\n" if kept else "") + TRUNC_MARK.format(n=len(text) - len(shown))


def read_summary(provider: LLMProvider, scope: Scope, addr: str, run_dir: Path, *,
                 retry_failed: bool = False) -> tuple[CalleeView, dict[str, Any] | None]:
    """The no-context (R4) summary of one function in scope, as a CalleeView for the D-026 renderer, plus
    analyze_function's row (None when there was no code to analyze). Rows and prompts go under run_dir."""
    f = _target(scope, addr, allow_root=False)
    name = _name(scope, addr)
    if not has_code(f):
        return CalleeView(addr=addr, name=name, status="decompile_failed"), None
    row = analyze_function(provider, scope.prog, addr, Path(run_dir), retry_failed=retry_failed)
    if row["record"] is not None:
        return CalleeView(addr=addr, name=name, status="ok", summary=row["record"]["summary"]), row
    return CalleeView(addr=addr, name=name, status="failed", failure=row.get("failure") or "unknown"), row
