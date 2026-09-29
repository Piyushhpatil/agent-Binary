"""Paired comparisons for the pre-registered tests, and the ablation strata (Phase 8, D-030).

Every rung scores the same 636 roots, so two rungs are compared root by root (paired), never by
overlapping intervals. For one comparison and one label, a root is right for a rung when its cell
is TP (bad root) or TN (good root); an abstention is wrong. Only the roots where the two rungs
disagree carry information: b = right for A only, c = right for B only. The exact McNemar test asks
whether a split that uneven is plausible if each disagreement were a fair coin: b ~ Binomial(b+c, 1/2).

The ten pre-registered tests (C1-C5, each on bad roots and on good roots) are corrected together with
Holm-Bonferroni at family-wise alpha 0.05, and only when all ten exist; a partial family gets raw p
values and no correction.

Ablation strata, per root: S0 the walk prompt had no callee block (context_chars == 0), so both arms
sent the same bytes and must agree; S1 a callee block but a one-member path; S2 a path with more than
one member. A disagreement in S0 is a bug and fails closed.

audit_prompts() is the byte-identity audit of the two arms: for every function with a no-context
row, the no-context prompt is the walk prompt with exactly one contiguous block removed, and both
used the same system prompt.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping

from taintwalk.analysis.callgraph import addr_key
from taintwalk.eval.score import discover_runs

ALPHA = 0.05
COMPARISONS = (("C1", "R7", "R6"), ("C2", "R5", "R4"), ("C3", "R7", "R3"),
               ("C4", "R7", "R2"), ("C5", "R7", "R5"))
LABELS = ("bad", "good")
RIGHT = {"bad": "TP", "good": "TN"}
Key = tuple[str, str]


class AblationError(RuntimeError):
    """The two sides of a comparison do not line up; nothing is compared."""


# ---- statistics -------------------------------------------------------------------------------

def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p value for b discordant pairs one way and c the other."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def holm(pvalues: Mapping[str, float], alpha: float = ALPHA) -> dict[str, dict[str, Any]]:
    """Holm-Bonferroni step-down over a family. Adjusted p = running max of (m - i) * p in ascending
    order, capped at 1; a hypothesis is rejected when its adjusted p is at most alpha."""
    order = sorted(pvalues.items(), key=lambda kv: (kv[1], kv[0]))
    m = len(order)
    out: dict[str, dict[str, Any]] = {}
    running = 0.0
    for i, (name, p) in enumerate(order):
        running = min(1.0, max(running, (m - i) * p))
        out[name] = {"p": p, "p_holm": round(running, 6), "reject": running <= alpha}
    return out


# ---- paired comparisons -------------------------------------------------------------------

def _index(roots: Iterable[dict[str, Any]], side: str) -> dict[Key, dict[str, Any]]:
    idx: dict[Key, dict[str, Any]] = {}
    for r in roots:
        k = (r["case_id"], r["addr"])
        if k in idx:
            raise AblationError(f"{side}: root {k} appears twice")
        idx[k] = r
    return idx


def paired(a_roots: list[dict[str, Any]], b_roots: list[dict[str, Any]],
           keys: Iterable[Key] | None = None) -> dict[str, dict[str, Any]]:
    """Per label: how many roots each rung gets right, the discordant counts, and the exact p."""
    ia, ib = _index(a_roots, "A"), _index(b_roots, "B")
    if set(ia) != set(ib):
        raise AblationError(f"the two rungs hold different roots ({len(set(ia) ^ set(ib))} differ)")
    use = sorted(ia) if keys is None else sorted(keys)
    out: dict[str, dict[str, Any]] = {}
    for label in LABELS:
        both = a_only = b_only = neither = 0
        for k in use:
            ra, rb = ia[k], ib[k]
            if ra["label"] != rb["label"]:
                raise AblationError(f"root {k} is {ra['label']} on one side and {rb['label']} on the other")
            if ra["label"] != label:
                continue
            a_ok, b_ok = ra["cell"] == RIGHT[label], rb["cell"] == RIGHT[label]
            both += a_ok and b_ok
            a_only += a_ok and not b_ok
            b_only += b_ok and not a_ok
            neither += not a_ok and not b_ok
        out[label] = {"n": both + a_only + b_only + neither, "a_right": both + a_only,
                      "b_right": both + b_only, "both": both, "a_only": a_only, "b_only": b_only,
                      "neither": neither, "p": mcnemar_exact(a_only, b_only)}
    return out


def preregistered_tests(roots_by_rung: Mapping[str, list[dict[str, Any]]],
                        alpha: float = ALPHA) -> dict[str, Any]:
    """C1-C5 on bad and good roots. Holm runs only on the complete family of ten."""
    tests: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for cid, a, b in COMPARISONS:
        if a not in roots_by_rung or b not in roots_by_rung:
            missing.append(cid)
            continue
        res = paired(roots_by_rung[a], roots_by_rung[b])
        for label in LABELS:
            tests[f"{cid}-{label}"] = {"comparison": cid, "a": a, "b": b, "label": label, **res[label]}
    applied = not missing
    if applied:
        for name, v in holm({k: t["p"] for k, t in tests.items()}, alpha).items():
            tests[name].update(p_holm=v["p_holm"], reject=v["reject"])
    return {"alpha": alpha, "family": 2 * len(COMPARISONS), "missing": missing,
            "holm_applied": applied, "tests": tests}


# ---- ablation strata ----------------------------------------------------------------------

def stratum_of(context_chars: int, members: list[str]) -> str:
    if len(members) > 1:
        if not context_chars:
            raise AblationError("a multi-member path whose root had no callee block")
        return "S2"
    return "S1" if context_chars else "S0"


def root_contexts(root: Path) -> dict[tuple[str, str], int]:
    """(binary sha256, addr) -> context_chars for every walked function under a walk root."""
    out: dict[tuple[str, str], int] = {}
    for d in discover_runs(Path(root)):
        walk = json.loads((d / "walk.json").read_text(encoding="utf-8"))
        for a, fn in walk["functions"].items():
            out[(walk["binary_sha256"], a)] = fn["context_chars"]
    if not out:
        raise AblationError(f"no walk.json at or under {root}")
    return out


def strata_of_roots(roots: list[dict[str, Any]], contexts: Mapping[tuple[str, str], int]) -> dict[Key, str]:
    out: dict[Key, str] = {}
    for r in roots:
        ctx = contexts.get((r["binary_sha256"], r["addr"]))
        if ctx is None:
            raise AblationError(f"{r['case_id']} {r['addr']}: root not found in the walk")
        out[(r["case_id"], r["addr"])] = stratum_of(ctx, r["members"])
    return out


def ablation(walk_roots: list[dict[str, Any]], base_roots: list[dict[str, Any]],
             strata: Mapping[Key, str]) -> dict[str, Any]:
    """Walk arm (A) against the no-context arm (B), overall and per stratum. S0 must agree exactly."""
    ia, ib = _index(walk_roots, "walk"), _index(base_roots, "no-context")
    if set(ia) != set(ib) or set(ia) != set(strata):
        raise AblationError("walk roots, no-context roots and strata do not cover the same roots")
    disagree = sorted(k for k in ia if strata[k] == "S0" and ia[k]["cell"] != ib[k]["cell"])
    if disagree:
        raise AblationError(f"S0 roots disagree between arms although their prompts are identical: {disagree[:3]}")
    out: dict[str, Any] = {"all": paired(walk_roots, base_roots)}
    for s in ("S0", "S1", "S2"):
        keys = [k for k in ia if strata[k] == s]
        out[s] = paired(walk_roots, base_roots, keys) if keys else None
    out["counts"] = {s: sum(1 for k in ia if strata[k] == s) for s in ("S0", "S1", "S2")}
    return out


# ---- prompt byte-identity audit ----------------------------------------------------------

def _prefix(a: str, b: str) -> int:
    lo, hi = 0, min(len(a), len(b))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if a[:mid] == b[:mid]:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _suffix(a: str, b: str, limit: int) -> int:
    lo, hi = 0, min(len(a), len(b), limit)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if a[len(a) - mid:] == b[len(b) - mid:]:
            lo = mid
        else:
            hi = mid - 1
    return lo


def single_insertion(base: str, walk: str) -> int | None:
    """Length of the one contiguous block that turns base into walk, or None if walk is not base with
    exactly one block inserted. Identical strings give 0."""
    if len(walk) < len(base):
        return None
    p = _prefix(base, walk)
    s = _suffix(base, walk, len(base) - p)
    return len(walk) - len(base) if p + s == len(base) else None


def audit_prompts(run_dir: Path) -> dict[str, Any]:
    """Every no-context prompt of one walk run dir against its walk prompt."""
    run_dir = Path(run_dir)
    walk = json.loads((run_dir / "walk.json").read_text(encoding="utf-8"))
    sha, base = walk["binary_sha256"], walk.get("baseline") or {}
    failures: list[tuple[str, str]] = []
    overhead: dict[int, int] = {}
    for a in sorted(base, key=addr_key):
        name = f"{sha[:12]}_{a}.json"
        wp, bp = run_dir / "prompts" / name, run_dir / "baseline" / "prompts" / name
        if not wp.exists() or not bp.exists():
            failures.append((a, "prompt file missing"))
            continue
        w = json.loads(wp.read_text(encoding="utf-8"))
        b = json.loads(bp.read_text(encoding="utf-8"))
        if w["system_sha256"] != b["system_sha256"]:
            failures.append((a, "system prompt differs"))
            continue
        ins = single_insertion(b["user"], w["user"])
        if not ins:
            failures.append((a, f"not exactly one inserted block (got {ins})"))
            continue
        d = ins - walk["functions"][a]["context_chars"]
        overhead[d] = overhead.get(d, 0) + 1
    return {"run_dir": run_dir.name, "checked": len(base), "failures": failures,
            "overhead": dict(sorted(overhead.items()))}


def audit_root(root: Path) -> dict[str, Any]:
    """audit_prompts over every walk run dir at or under root."""
    runs = discover_runs(Path(root))
    checked, failures, overhead = 0, [], {}
    for d in runs:
        a = audit_prompts(d)
        checked += a["checked"]
        failures += [(d.name, *f) for f in a["failures"]]
        for k, v in a["overhead"].items():
            overhead[k] = overhead.get(k, 0) + v
    return {"run_dirs": len(runs), "checked": checked, "failures": failures,
            "overhead": dict(sorted(overhead.items()))}