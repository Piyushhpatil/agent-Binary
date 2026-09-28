"""Bottom-up interprocedural walk over one program.json (Phase 6, D-026). Analysis side, label-free.

For each component of the walk plan (callees first; analysis/callgraph.py):
    callee views -> render_callee_context -> analyze_function(callee_context=...) -> row
A recursive component is re-analyzed until the rendered view of every member (the exact text
a caller would see) stops changing, or max_iterations. Iterations are Jacobi-style: iteration k
sees its siblings' iteration k-1 rows; iteration 0 sees them as "not yet available". The cap,
not the model, guarantees termination: an LLM is not monotone on a lattice.

Isolated functions are skipped (callgraph.plan_walk). Their prompt would equal the per-function
prompt. One edge case: a function whose only callees are out of scope counts as isolated too,
although its prompt would carry an information-free stub line. The Juliet corpus has none.

Writes, under the run dir (I2):
    system.txt, prompts/<stem>[.itN].json, summaries/<stem>[.itN].json    (analyze_function)
    summaries.json   addr -> final SummaryRecord, null for a terminal failure; sorted keys
    walk.json        plan, skipped, components, per-function callee context and status
    baseline/        with_baseline: callers again with no callee context (a diagnostic only)
LeakError is never caught: model output that trips the gate aborts the walk (D-017, D-026).
explain_function() rebuilds what one prompt carried from these files alone, with no model call.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from taintwalk.analysis.analyze_one import analyze_function, stem
from taintwalk.analysis.callgraph import CallGraph, addr_key, build_graph, plan_walk
from taintwalk.analysis.prompts import (
    CALLEE_CONTEXT_VERSION,
    CALLEE_HEADER,
    PROMPT_VERSION,
    SYSTEM,
    CalleeView,
    prepare_code,
    render_callee_context,
)
from taintwalk.llm.base import LLMProvider

VIEW_RENDER_MAX = 1_000_000     # convergence compares full rendered views, never truncated


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _name(prog: dict[str, Any], fns: dict[str, dict], addr: str) -> str:
    f = fns.get(addr)
    if f is not None:
        return f["ghidra_name"]
    return f"FUN_{int(addr, 16) + int(prog['binary']['image_base'], 16):08x}"


def _analyzable(f: dict[str, Any]) -> bool:
    return not f.get("decompile_failed") and bool(f.get("pseudo_c"))


def _view(addr: str, fns: dict[str, dict], graph: CallGraph, rows: dict[str, dict],
          pending: frozenset[str], prog: dict[str, Any]) -> CalleeView:
    name = _name(prog, fns, addr)
    if addr not in graph.succ:
        return CalleeView(addr, name, "out_of_scope")
    if not _analyzable(fns[addr]):
        return CalleeView(addr, name, "decompile_failed")
    if addr in pending:
        return CalleeView(addr, name, "recursive_pending")
    row = rows[addr]
    if row["status"] == "ok" and row["record"] is not None:
        return CalleeView(addr, name, "ok", summary=row["record"]["summary"])
    return CalleeView(addr, name, "failed", failure=row.get("failure") or "unknown")


def _signature(addr: str, rows: dict[str, dict], fns: dict[str, dict], graph: CallGraph,
               prog: dict[str, Any]) -> str:
    """What a caller would see of `addr` given these rows."""
    view = _view(addr, fns, graph, rows, frozenset(), prog)
    return render_callee_context((), [view], max_chars=VIEW_RENDER_MAX).text


def _analyze_in_walk(provider: LLMProvider, prog: dict[str, Any], fns: dict[str, dict], graph: CallGraph,
                     addr: str, visible: dict[str, dict], pending: frozenset[str], run_dir: Path, *,
                     max_chars: int, tag: str, iteration: int, retry_failed: bool) -> dict[str, Any]:
    sha = prog["binary"]["sha256"]
    f = fns[addr]
    callees = sorted(set(graph.succ[addr]) | set(graph.stubs[addr]), key=addr_key)
    views = [_view(c, fns, graph, visible, pending, prog) for c in callees]
    info: dict[str, Any] = {
        "callee_context_version": CALLEE_CONTEXT_VERSION,
        "iteration": iteration,
        "tag": tag,
        "callee_statuses": {v.addr: v.status for v in views},
    }
    if not _analyzable(f):
        info.update(callees=[], omitted=[], context_chars=0)
        row = {"binary_sha256": sha, "address": addr, "function": f["ghidra_name"], "status": "failed",
               "failure": "decompile_failed", "record": None, "cache_hit": False, "usage": None,
               "wall_s": 0.0, "repaired": False, "chars_per_token": [], "evidence_issues": [], "walk": info}
        _write_json(Path(run_dir) / "summaries" / f"{stem(sha, addr)}{tag}.json", row)
        return row
    ctx = render_callee_context(prepare_code(f["pseudo_c"])[0], views, max_chars=max_chars)
    info.update(callees=list(ctx.order), omitted=list(ctx.omitted), context_chars=len(ctx.text))
    return analyze_function(provider, prog, addr, run_dir, retry_failed=retry_failed,
                            callee_context=ctx.text, tag=tag, extra={"walk": info})


def _row_line(k: int, row: dict[str, Any]) -> str:
    w = row.get("walk", {})
    when = "CACHE" if row.get("cache_hit") else f"{row.get('wall_s', 0.0):.1f}s"
    fail = f" {row['failure']}" if row["status"] != "ok" else ""
    ctx = f"callees {len(w.get('callees', []))}" + (f" omitted {len(w['omitted'])}" if w.get("omitted") else "")
    return f"[{k:>4}] {row['address']}{w.get('tag', '')}  {row['status']}{fail}  {when}  {ctx}"


def walk_program(provider: LLMProvider, prog: dict[str, Any], run_dir: Path, *, max_chars: int,
                 max_iterations: int, retry_failed: bool = False, with_baseline: bool = False,
                 log: Callable[[str], None] = print) -> dict[str, Any]:
    if max_iterations < 1:
        raise ValueError("max_iterations must be at least 1")
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "system.txt").write_text(SYSTEM, encoding="utf-8")
    sha = prog["binary"]["sha256"]
    fns = {f["addr"]: f for f in prog["functions"]}
    graph = build_graph(prog)
    plan = plan_walk(graph)                       # verify_order runs inside; fails closed

    rows: dict[str, dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []

    def run(addr: str, visible: dict[str, dict], pending: frozenset[str], tag: str, it: int) -> dict[str, Any]:
        row = _analyze_in_walk(provider, prog, fns, graph, addr, visible, pending, run_dir,
                               max_chars=max_chars, tag=tag, iteration=it, retry_failed=retry_failed)
        calls.append(row)
        log(_row_line(len(calls), row))
        return row

    for comp in plan.order:
        if not comp.recursive:
            a = comp.members[0]
            rows[a] = run(a, rows, frozenset(), "", 0)
            components.append({"members": [a], "recursive": False, "iterations": 1, "converged": True})
            continue
        prev: dict[str, dict[str, Any]] = {}
        prev_sig: dict[str, str] | None = None
        converged, iterations = False, 0
        for it in range(max_iterations):
            visible = {**rows, **prev}
            pending = frozenset(m for m in comp.members if m not in prev)
            cur = {m: run(m, visible, pending, f".it{it}", it) for m in comp.members}
            iterations = it + 1
            sig = {m: _signature(m, cur, fns, graph, prog) for m in comp.members}
            prev = cur
            if sig == prev_sig:
                converged = True
                break
            prev_sig = sig
        rows.update(prev)
        components.append({"members": list(comp.members), "recursive": True,
                           "iterations": iterations, "converged": converged})

    baseline: dict[str, dict[str, Any]] = {}
    if with_baseline:
        bdir = run_dir / "baseline"
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / "system.txt").write_text(SYSTEM, encoding="utf-8")
        for a in plan.functions:
            if rows[a]["walk"]["context_chars"] and _analyzable(fns[a]):
                baseline[a] = analyze_function(provider, prog, a, bdir, retry_failed=retry_failed)
                calls.append(baseline[a])
                log(_row_line(len(calls), baseline[a]) + "  baseline")

    _write_json(run_dir / "summaries.json", {a: rows[a]["record"] for a in plan.functions})
    _write_json(run_dir / "walk.json", {
        "binary_sha256": sha,
        "prompt_version": PROMPT_VERSION,
        "callee_context_version": CALLEE_CONTEXT_VERSION,
        "provider": provider.identity(),
        "max_chars": max_chars,
        "max_iterations": max_iterations,
        "plan": [{"members": list(c.members), "recursive": c.recursive} for c in plan.order],
        "components": components,
        "skipped_isolated": list(plan.skipped_isolated),
        "functions": {a: {"function": rows[a]["function"], "status": rows[a]["status"],
                          "failure": rows[a].get("failure"), "cache_hit": rows[a].get("cache_hit"),
                          **rows[a]["walk"]} for a in plan.functions},
        "baseline": {a: {"status": r["status"], "failure": r.get("failure"), "cache_hit": r.get("cache_hit")}
                     for a, r in baseline.items()},
    })
    return {"run_dir": run_dir, "plan": plan, "rows": rows, "calls": calls,
            "components": components, "baseline": baseline}


def _mechanism(row: dict[str, Any]) -> str:
    return row["record"]["summary"]["verdict"]["mechanism"] if row.get("record") else "no summary"


def walk_report(result: dict[str, Any]) -> int:
    """Label-free report. 0 when every walked function has a summaries.json entry and no
    prompt overflowed its context; terminal model failures are counted, not gate failures."""
    plan, rows, calls, base = result["plan"], result["rows"], result["calls"], result["baseline"]
    fns = plan.functions
    n = len(fns)
    ok = sum(rows[a]["status"] == "ok" for a in fns)
    failures = Counter(rows[a]["failure"] for a in fns if rows[a]["status"] != "ok")
    live = [r for r in calls if not r.get("cache_hit") and r.get("usage")]
    cpt = [c for r in calls for c in r.get("chars_per_token", []) if isinstance(c, (int, float))]
    with_ctx = sum(bool(rows[a]["walk"]["context_chars"]) for a in fns)
    omitted = sum(len(rows[a]["walk"]["omitted"]) for a in fns)
    rec = [c for c in result["components"] if c["recursive"]]
    unconverged = [c for c in rec if not c["converged"]]
    overflow = sum(r.get("failure") == "context_overflow" for r in calls)
    gated = len([r for r in calls if r.get("usage") is not None or r.get("cache_hit")]) \
        + sum(bool(r.get("repaired")) and not r.get("cache_hit") for r in calls)
    summaries = json.loads((Path(result["run_dir"]) / "summaries.json").read_text(encoding="utf-8"))
    complete = n > 0 and set(summaries) == set(fns) == set(rows)

    print(f"\nwalked             : {n}  skipped isolated {len(plan.skipped_isolated)}  "
          f"components {len(result['components'])} (recursive {len(rec)})")
    print("walk order         : verified, every callee before its caller")
    print(f"summaries          : {ok}/{n} ok  entries {len(summaries)}/{n}  failures {dict(failures)}")
    print(f"callee context     : {with_ctx} functions with context, {omitted} callees omitted (budget)")
    print(f"recursion          : {len(rec)} recursive components, {len(unconverged)} unconverged at the cap")
    print(f"context overflow   : {overflow}   [must be 0]")
    print(f"chars/token        : " + (f"min {min(cpt)} mean {statistics.mean(cpt):.2f} max {max(cpt)}" if cpt else "n/a"))
    print(f"tokens (this run)  : in {sum(r['usage']['input_tokens'] for r in live)}  "
          f"out {sum(r['usage']['output_tokens'] for r in live)}  "
          f"model time {sum(r['wall_s'] for r in live):.1f} s  cache hits {sum(bool(r.get('cache_hit')) for r in calls)}"
          f" of {len(calls)} calls")
    print(f"leak gate          : {gated} prompts gated before any I/O; 0 violations (a violation aborts the walk)")
    print(f"summaries.json     : {Path(result['run_dir']) / 'summaries.json'}")
    if base:
        changed = [a for a in base if _mechanism(base[a]) != _mechanism(rows[a])]
        print(f"baseline           : callee context changed the verdict of {len(changed)} of {len(base)} "
              f"functions (diagnostic, not a metric)")
        for a in changed:
            print(f"    {a} {rows[a]['function']}  no context: {_mechanism(base[a])}  ->  walk: {_mechanism(rows[a])}")
    passed = complete and overflow == 0
    print("WALK OK" if passed else "WALK FAIL")
    return 0 if passed else 1


def _verdict_text(record: dict[str, Any] | None) -> str:
    if not record:
        return "no summary"
    v = record["summary"]["verdict"]
    if v["mechanism"] == "none":
        return "not vulnerable"
    detail = "/".join(x for x in (v["region"], v["access"], v["direction"]) if x != "not_applicable")
    return f"vulnerable, {v['mechanism']}" + (f" {detail}" if detail else "")


def explain_function(run_dir: Path, addr: str) -> int:
    """`walk --explain ADDR`: what the walk injected into one function's prompt and what it
    concluded, with and without that context. Reads the run dir only; no model call (I2)."""
    run_dir = Path(run_dir)
    wpath = run_dir / "walk.json"
    if not wpath.exists():
        print(f"no walk.json in {run_dir}; run the walk first")
        return 2
    walk = json.loads(wpath.read_text(encoding="utf-8"))
    sha = walk["binary_sha256"]
    info = walk["functions"].get(addr)
    if info is None:
        why = ("skipped as isolated: its summary is exactly the per-function one"
               if addr in walk["skipped_isolated"] else "not in this walk")
        print(f"{addr}: {why}")
        return 2
    s = stem(sha, addr) + info.get("tag", "")
    ppath = run_dir / "prompts" / f"{s}.json"
    prompt = json.loads(ppath.read_text(encoding="utf-8")) if ppath.exists() else None
    row = json.loads((run_dir / "summaries" / f"{s}.json").read_text(encoding="utf-8"))
    bpath = run_dir / "baseline" / "summaries" / f"{stem(sha, addr)}.json"
    base = json.loads(bpath.read_text(encoding="utf-8")) if bpath.exists() else None

    status = info["status"] + (f" ({info['failure']})" if info["status"] != "ok" else "")
    statuses = info.get("callee_statuses", {})
    print(f"explain {addr} {info['function']}   binary {sha[:12]}   run {run_dir}")
    print(f"status        : {status}   iteration {info.get('iteration', 0)}")
    print("callees       : " + (", ".join(f"{a} {st}" for a, st in statuses.items()) or "none"))
    if info.get("omitted"):
        print(f"omitted       : {info['omitted']} (budget)")
    print(f"walk verdict  : {_verdict_text(row.get('record'))}")
    print(f"no context    : {_verdict_text(base.get('record')) if base else 'not run (walk with --with-baseline)'}")
    user = prompt["user"] if prompt else ""
    i = user.find(CALLEE_HEADER)
    print("--- callee block injected into the prompt ---")
    print(user[i:].rstrip("\n") if i >= 0 else
          "(none: no callee context; this prompt equals the per-function prompt)")
    print("--- end ---")
    return 0