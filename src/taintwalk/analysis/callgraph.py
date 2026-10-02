"""Call graph, SCCs and bottom-up walk order for one program.json (Phase 6, D-026).

Analysis side, label-free: reads only program.json fields (addr, in_scope, callees).

- Edges are internal callees whose target is in scope. An internal callee outside scope, or
  at an address with no in-scope record, is kept aside as a stub target, never an edge.
- SCCs by Tarjan's algorithm, iterative so a deep call chain in real code (Phase 9) cannot
  hit Python's recursion limit. Tarjan emits a component only after every component it can
  reach, so its emission order is already callees-first: the bottom-up schedule.
- Isolated functions (no in-scope caller, no in-scope callee, no self-loop) are left out of
  the walk: their walk prompt would equal the per-function prompt (D-026).
- Nodes and successors are ordered by numeric address, so the plan is deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def addr_key(addr: str) -> int:
    return int(addr, 16)


@dataclass(frozen=True)
class CallGraph:
    nodes: tuple[str, ...]                     # in-scope addrs, numeric order
    succ: dict[str, tuple[str, ...]]           # in-scope internal callees (a self-loop included)
    pred: dict[str, tuple[str, ...]]           # in-scope callers
    stubs: dict[str, tuple[str, ...]]          # internal callees with no in-scope record

    @property
    def edges(self) -> int:
        return sum(len(v) for v in self.succ.values())

    def is_isolated(self, addr: str) -> bool:
        return not self.succ[addr] and not self.pred[addr]


@dataclass(frozen=True)
class Component:
    members: tuple[str, ...]                   # numeric order
    recursive: bool                            # size > 1, or a self-loop


@dataclass(frozen=True)
class WalkPlan:
    order: tuple[Component, ...]               # callees first
    skipped_isolated: tuple[str, ...]
    scope: tuple[str, ...] | None = None       # Phase 9 roots walk: the roots' downward closure
    roots: tuple[str, ...] = ()                # Phase 9 roots walk: walked even when isolated

    def position(self) -> dict[str, int]:
        return {a: i for i, c in enumerate(self.order) for a in c.members}

    @property
    def functions(self) -> tuple[str, ...]:
        return tuple(a for c in self.order for a in c.members)


def build_graph(prog: dict[str, Any]) -> CallGraph:
    in_scope_fns = [f for f in prog["functions"] if f["in_scope"]]
    by_addr = {f["addr"]: f for f in in_scope_fns}
    if len(by_addr) != len(in_scope_fns):
        raise ValueError("program.json has duplicate in-scope addresses")
    nodes = tuple(sorted(by_addr, key=addr_key))

    succ: dict[str, tuple[str, ...]] = {}
    stubs: dict[str, tuple[str, ...]] = {}
    for a in nodes:
        inner: set[str] = set()
        outer: set[str] = set()
        for c in by_addr[a]["callees"]:
            if c["kind"] != "internal":
                continue
            (inner if c["addr"] in by_addr else outer).add(c["addr"])
        succ[a] = tuple(sorted(inner, key=addr_key))
        stubs[a] = tuple(sorted(outer, key=addr_key))

    pred: dict[str, list[str]] = {a: [] for a in nodes}
    for u in nodes:
        for v in succ[u]:
            pred[v].append(u)
    return CallGraph(
        nodes=nodes,
        succ=succ,
        pred={a: tuple(sorted(p, key=addr_key)) for a, p in pred.items()},
        stubs=stubs,
    )


def tarjan_sccs(nodes: tuple[str, ...], succ: dict[str, tuple[str, ...]]) -> list[tuple[str, ...]]:
    """Strongly connected components in emission order (callees first). Iterative."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    out: list[tuple[str, ...]] = []
    counter = 0

    for root in nodes:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(succ[root]))]
        while work:
            v, it = work[-1]
            descended = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(succ[w])))
                    descended = True
                    break
                if w in on_stack:
                    low[v] = min(low[v], index[w])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                comp: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                out.append(tuple(sorted(comp, key=addr_key)))
    return out


def verify_order(plan: WalkPlan, graph: CallGraph) -> None:
    """Fail closed unless every function is walked or skipped exactly once and every callee is
    scheduled no later than its caller (in the same component only when it is recursive)."""
    pos = plan.position()
    listed = list(pos) + list(plan.skipped_isolated)
    expected = set(graph.nodes) if plan.scope is None else set(plan.scope)
    if len(listed) != len(set(listed)) or set(listed) != expected:
        raise ValueError("walk plan does not cover every in-scope function exactly once"
                         if plan.scope is None else "walk plan does not cover its roots' closure exactly once")
    unwalked = [r for r in plan.roots if r not in pos]
    if unwalked:
        raise ValueError(f"walk plan skips roots {unwalked[:5]}")
    for u, pu in pos.items():
        for v in graph.succ[u]:
            if v not in pos:
                raise ValueError(f"walk order: callee {v} of {u} is not scheduled")
            if pos[v] > pu:
                raise ValueError(f"walk order: callee {v} scheduled after caller {u}")
            if pos[v] == pu and not plan.order[pu].recursive:
                raise ValueError(f"walk order: {u} and {v} share a non-recursive component")


def downward_closure(graph: CallGraph, roots: tuple[str, ...]) -> frozenset[str]:
    """The roots plus every in-scope function reachable from them (Phase 9). Fails closed on a root
    that is not an in-scope function."""
    missing = [r for r in roots if r not in graph.succ]
    if missing:
        raise ValueError(f"roots are not in-scope functions: {missing[:5]}")
    seen, stack = set(roots), list(roots)
    while stack:
        for c in graph.succ[stack.pop()]:
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return frozenset(seen)


def plan_walk(graph: CallGraph, roots: tuple[str, ...] | None = None) -> WalkPlan:
    """The whole program (roots=None, Phases 6-8), or only the roots' downward closure (Phase 9).

    A function's prompt depends only on its own code and its callees' summaries, and a downward
    closure contains every callee of its members, so a roots walk gives each function in it exactly
    the prompt a whole-program walk gives it. Roots are walked even when isolated: they are scored."""
    if roots is None:
        keep, forced = graph.nodes, frozenset()
    else:
        if not roots:
            raise ValueError("roots must name at least one function")
        scope = downward_closure(graph, roots)
        keep, forced = tuple(a for a in graph.nodes if a in scope), frozenset(roots)
    walk_nodes = tuple(a for a in keep if a in forced or not graph.is_isolated(a))
    skipped = tuple(a for a in keep if a not in forced and graph.is_isolated(a))
    comps = tuple(
        Component(members=m, recursive=len(m) > 1 or m[0] in graph.succ[m[0]])
        for m in tarjan_sccs(walk_nodes, graph.succ)
    )
    plan = WalkPlan(order=comps, skipped_isolated=skipped,
                    scope=None if roots is None else keep,
                    roots=() if roots is None else tuple(sorted(set(roots), key=addr_key)))
    verify_order(plan, graph)
    return plan