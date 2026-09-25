"""Deterministic Juliet case selection for the TaintWalk corpus (D-011, D-013).

Output is a list of *groups*, one per (cwe, flow, stratum). Each group has
`need` slots and a seeded, ranked candidate list. The builder takes the first
`need` candidates that compile; the rest are same-cell, same-stratum
substitutes, so a build failure never unbalances the corpus.
No compilation happens here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from taintwalk.config import REPO_ROOT, load_config

CASE_FILE = re.compile(r"^CWE(\d+)_[A-Za-z0-9_]+?__(.+)_(\d{2})([a-z]?)\.(c|cpp)$")

CaseKey = tuple[int, str, str]  # (cwe, functional_variant, flow)


def corpus_cfg() -> dict[str, Any]:
    return load_config()["corpus"]


def source_kind(functional: str, c: dict[str, Any]) -> str:
    return "external" if any(t in functional for t in c["external_sources"]) else "fixed"


def sink_kind(cwe: int, functional: str, c: dict[str, Any]) -> str:
    """Only meaningful for the stratified buffer classes; 'n/a' elsewhere."""
    if cwe not in {int(x) for x in c["stratified_cwes"]}:
        return "n/a"
    if source_kind(functional, c) == "external":
        return "index"
    if any(t in functional for t in c["fixed_call_tokens"]):
        return "call"
    if any(t in functional for t in c["fixed_loop_tokens"]):
        return "loop"
    return "other"


def index_cases(juliet_root: Path) -> dict[CaseKey, list[str]]:
    """Map every C-only, non-Windows Juliet case to its source files
    (paths relative to juliet_root, sorted)."""
    tc = juliet_root / "testcases"
    if not tc.is_dir():
        raise SystemExit(f"SELECT FAIL: no testcases dir at {tc}")
    exts: dict[CaseKey, set[str]] = {}
    files: dict[CaseKey, list[str]] = {}
    for f in sorted(tc.rglob("*")):
        if not f.is_file() or f.suffix not in (".c", ".cpp"):
            continue
        m = CASE_FILE.match(f.name)
        if not m:
            continue
        key = (int(m.group(1)), m.group(2), m.group(3))
        exts.setdefault(key, set()).add(m.group(5))
        files.setdefault(key, []).append(f.relative_to(juliet_root).as_posix())
    return {k: sorted(v) for k, v in files.items()
            if exts[k] == {"c"} and "w32" not in k[1]}


def _case_record(k: CaseKey, files: list[str], c: dict[str, Any]) -> dict[str, Any]:
    return {"cwe": k[0], "functional": k[1], "flow": k[2],
            "source_kind": source_kind(k[1], c),
            "sink_kind": sink_kind(k[0], k[1], c),
            "files": files}


def select(c: dict[str, Any] | None = None) -> dict[str, Any]:
    c = c or corpus_cfg()
    cases = index_cases(REPO_ROOT / c["juliet_root"])
    rng = random.Random(int(c["seed"]))
    cwes = [int(x) for x in c["cwes"]]
    flows = [str(x) for x in c["flows"]]
    strat = {int(x) for x in c["stratified_cwes"]}
    fixed_tokens = list(c["fixed_call_tokens"]) + list(c["fixed_loop_tokens"])
    per_cell = int(c["per_cell"])

    cells = [(w, f) for w in cwes for f in flows]
    n_extra = int(c["total"]) - per_cell * len(cells)
    if not 0 <= n_extra <= len(cells):
        raise SystemExit(f"SELECT FAIL: total {c['total']} incompatible with "
                         f"{len(cells)} cells x {per_cell}")
    extra_cells = set(rng.sample(cells, n_extra))

    groups: list[dict[str, Any]] = []
    short: list[str] = []
    for cwe, flow in cells:
        keys = sorted(k for k in cases if k[0] == cwe and k[2] == flow)
        pools = {
            "external": [k for k in keys if source_kind(k[1], c) == "external"],
            "fixed_sink": [k for k in keys if source_kind(k[1], c) == "fixed"
                           and any(t in k[1] for t in fixed_tokens)],
        }
        bonus = 1 if (cwe, flow) in extra_cells else 0
        if cwe in strat:   # 1 external + 1 fixed call/loop sink; extra -> fixed_sink
            plan = {"external": per_cell - per_cell // 2,
                    "fixed_sink": per_cell // 2 + bonus}
        else:              # all external; extra -> external
            plan = {"external": per_cell + bonus}
        for stratum, need in plan.items():
            pool = list(pools[stratum])
            rng.shuffle(pool)
            if len(pool) < need:
                short.append(f"CWE-{cwe} flow {flow} {stratum}: need {need}, have {len(pool)}")
            groups.append({"cwe": cwe, "flow": flow, "stratum": stratum, "need": need,
                           "ranked": [_case_record(k, cases[k], c) for k in pool]})
    if short:
        raise SystemExit("SELECT FAIL: pools too small:\n  " + "\n  ".join(short))
    return {"seed": int(c["seed"]), "total": int(c["total"]), "groups": groups}


def digest(sel: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(sel, sort_keys=True).encode()).hexdigest()


def summarize(sel: dict[str, Any]) -> list[str]:
    g = sel["groups"]
    per_cell: Counter = Counter()
    strata: Counter = Counter()
    for x in g:
        per_cell[(x["cwe"], x["flow"])] += x["need"]
        strata[x["stratum"]] += x["need"]
    tight = min(g, key=lambda x: len(x["ranked"]) - x["need"])
    return [
        f"SELECT: {sum(per_cell.values())} slots, {len({k[0] for k in per_cell})} CWEs, "
        f"{len({k[1] for k in per_cell})} flows, {len(per_cell)} cells, "
        f"per-cell min {min(per_cell.values())} max {max(per_cell.values())}",
        f"strata: " + ", ".join(f"{k}={v}" for k, v in sorted(strata.items())),
        f"tightest pool: CWE-{tight['cwe']} flow {tight['flow']} {tight['stratum']} "
        f"need {tight['need']} of {len(tight['ranked'])} (spare {len(tight['ranked']) - tight['need']})",
        f"digest: {digest(sel)}",
    ]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m taintwalk.corpus.select",
                                description="Print the deterministic corpus selection summary.")
    p.parse_args(argv)
    for line in summarize(select()):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
