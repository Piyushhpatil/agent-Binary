"""Call graph, Tarjan SCCs and bottom-up walk order (Phase 6, D-026)."""
from __future__ import annotations

import json
import random

import pytest

from taintwalk.analysis.callgraph import (
    Component,
    WalkPlan,
    build_graph,
    plan_walk,
    verify_order,
)
from taintwalk.config import REPO_ROOT, load_config


def fn(addr: str, callees=(), *, in_scope: bool = True, external=()) -> dict:
    return {
        "addr": addr,
        "in_scope": in_scope,
        "callees": [{"kind": "internal", "addr": c} for c in callees]
                   + [{"kind": "external", "name": n} for n in external],
    }


def prog(*fns: dict) -> dict:
    return {"functions": list(fns)}


def order(plan: WalkPlan) -> list[tuple[str, ...]]:
    return [c.members for c in plan.order]


def test_chain_is_bottom_up():
    p = plan_walk(build_graph(prog(fn("0x10", ["0x20"]), fn("0x20", ["0x30"]), fn("0x30"))))
    assert order(p) == [("0x30",), ("0x20",), ("0x10",)]
    assert not any(c.recursive for c in p.order)


def test_diamond_callees_first():
    g = build_graph(prog(fn("0x1", ["0x2", "0x3"]), fn("0x2", ["0x4"]), fn("0x3", ["0x4"]), fn("0x4")))
    f = plan_walk(g).functions
    assert f[0] == "0x4" and f[-1] == "0x1" and set(f) == {"0x1", "0x2", "0x3", "0x4"}


def test_self_loop_is_a_recursive_singleton():
    p = plan_walk(build_graph(prog(fn("0x1", ["0x2"]), fn("0x2", ["0x2"]))))
    assert order(p) == [("0x2",), ("0x1",)]
    assert p.order[0].recursive and not p.order[1].recursive


def test_cycle_is_condensed_before_its_caller():
    g = build_graph(prog(fn("0x3", ["0x1"]), fn("0x1", ["0x2"]), fn("0x2", ["0x1", "0x4"]), fn("0x4")))
    p = plan_walk(g)
    assert order(p) == [("0x4",), ("0x1", "0x2"), ("0x3",)]
    assert p.order[1].recursive


def test_out_of_scope_and_unknown_callees_are_stubs_not_edges():
    g = build_graph(prog(fn("0x1", ["0x2", "0x5", "0x9"], external=["memcpy"]),
                         fn("0x2"), fn("0x5", in_scope=False)))
    assert g.succ["0x1"] == ("0x2",)
    assert g.stubs["0x1"] == ("0x5", "0x9")
    assert g.edges == 1 and g.nodes == ("0x1", "0x2")


def test_isolated_functions_are_skipped_and_counted():
    p = plan_walk(build_graph(prog(fn("0x1", ["0x2"]), fn("0x2"), fn("0x7"), fn("0x8", ["0x8"]))))
    assert p.skipped_isolated == ("0x7",)
    assert set(p.functions) == {"0x1", "0x2", "0x8"}


def test_addresses_are_ordered_numerically():
    g = build_graph(prog(fn("0x10"), fn("0x9"), fn("0xa")))
    assert g.nodes == ("0x9", "0xa", "0x10")


def test_plan_is_independent_of_input_order():
    base = [fn(f"0x{i:x}", [f"0x{j:x}" for j in range(i + 1, min(i + 4, 40))]) for i in range(1, 40)]
    base[-1]["callees"].append({"kind": "internal", "addr": "0x5"})     # back edge: one big SCC
    ref = plan_walk(build_graph(prog(*base)))
    assert any(c.recursive for c in ref.order)
    rng = random.Random(0)
    for _ in range(20):
        fs = [dict(f, callees=rng.sample(f["callees"], len(f["callees"]))) for f in base]
        rng.shuffle(fs)
        assert plan_walk(build_graph(prog(*fs))) == ref


def test_deep_chain_needs_no_recursion():
    n = 5000                                  # far past Python's default recursion limit
    fs = [fn(f"0x{i:x}", [f"0x{i + 1:x}"] if i < n else []) for i in range(1, n + 1)]
    p = plan_walk(build_graph(prog(*fs)))
    assert p.functions[0] == f"0x{n:x}" and p.functions[-1] == "0x1"


def test_verify_order_fails_closed():
    g = build_graph(prog(fn("0x1", ["0x2"]), fn("0x2")))
    caller_first = WalkPlan((Component(("0x1",), False), Component(("0x2",), False)), ())
    with pytest.raises(ValueError, match="after caller"):
        verify_order(caller_first, g)
    missing = WalkPlan((Component(("0x2",), False),), ())
    with pytest.raises(ValueError, match="exactly once"):
        verify_order(missing, g)


def _brute_sccs(nodes, succ) -> set[frozenset[str]]:
    reach = {}
    for a in nodes:
        seen, st = set(), list(succ[a])
        while st:
            u = st.pop()
            if u not in seen:
                seen.add(u)
                st.extend(succ[u])
        reach[a] = seen
    return {frozenset({a} | {b for b in reach[a] if a in reach[b]}) for a in nodes}


def test_corpus_tarjan_matches_brute_force_and_spike_counts():
    d = REPO_ROOT / load_config()["extract"]["out_dir"] / "programs"
    files = sorted(d.glob("*.json"))
    assert len(files) == 240, f"expected 240 program.json files in {d}; run the Phase 2 extract"
    nodes = edges = skipped = walked = recursive = 0
    for fp in files:
        g = build_graph(json.loads(fp.read_text(encoding="utf-8")))
        p = plan_walk(g)                                        # verify_order runs inside
        walk_nodes = [a for a in g.nodes if not g.is_isolated(a)]
        assert {frozenset(c.members) for c in p.order} == _brute_sccs(walk_nodes, g.succ), fp.name
        nodes += len(g.nodes)
        edges += g.edges
        skipped += len(p.skipped_isolated)
        walked += len(p.functions)
        recursive += sum(c.recursive for c in p.order)
    # Independent numbers from runs/p6-spike/cg_survey.py (D-026).
    assert (nodes, edges, skipped, walked, recursive) == (11029, 2755, 8707, 2322, 0)