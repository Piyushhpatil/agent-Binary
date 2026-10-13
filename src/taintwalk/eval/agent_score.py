"""Phase 10 scorer (D-042): R4, A1, A2 and R5 at the same Juliet roots, from persisted files only.

Four rungs, one judge. R4 is the no-context floor (Phase 8 baseline rows), A1 the scripted policy,
A2 the agent policy, R5 the fixed walk. The evidence block is the only input that differs, so a
difference between cells is attributable to it.

Four rules fail the scorer closed, each guarding one way the comparison could be a lie:
  1. a zero-fetch root whose A-cell differs from its R4 cell -> the harness itself adds something;
  2. a root whose metered total exceeds its cap        -> the caps did not hold;
  3. any taintwalk.llm module loaded in this process   -> a model could have been called while scoring;
  4. a root missing from any rung                      -> an incomplete run (a ceilinged run is void).

Real code (mini-step 9b): the same four rungs at the 24 Phase 9 roots, scored as D-040 pairs. The
roots, R4 and R5 come from real_score.py's own loaders, imported rather than re-written, so they are
the rows the Phase 9 gate validated. A1 and A2 come from <real-agent-root>/<policy>/<case_id>/. Rules
1, 2 and 4 apply there too. Descriptive only, no tests (D-042).

Reads only. Byte-identical on unchanged input. Splices one section into RESULTS.md.

    python -m taintwalk.eval.agent_score --dev            # development slice, not reportable
    python -m taintwalk.eval.agent_score --results-md docs/RESULTS.md
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any

from taintwalk.config import REPO_ROOT, load_config
from taintwalk.eval.ablation import preregistered_tests
from taintwalk.eval.metrics import OUTCOMES, _cell, confusion, score_rung
from taintwalk.eval.real_score import (
    PAIR_OUTCOMES, SHORT, RealScoreError, _pair_counts, load_roots, pair_outcome, r4_doc, r5_doc,
)

# NOTE: analyze_one is deliberately NOT imported. It pulls in taintwalk.llm, which would trip this
# module's own rule 3 (no provider module may be loaded while scoring) on the very first call.
# real_score.py builds the same path inline for the same reason. _stem must stay identical to
# analysis.analyze_one.stem, and test_agent_score.py asserts that against the real function.
SCORE_VERSION = 1
BEGIN, END = "<!-- phase10:begin -->", "<!-- phase10:end -->"

# The pre-registered family (D-042): 3 comparisons x 2 label sets = 6 tests, Holm at 0.05.
P10_COMPARISONS = (("A2vR5", "A2", "R5"), ("A2vA1", "A2", "A1"), ("A2vR4", "A2", "R4"))
RUNGS = ("R4", "A1", "A2", "R5")

# metrics.confusion() returns the rates at the top level and the D-008 counts nested under "cells"
# (probed 2026-10-08: keys cells, coverage, f1, negatives, positives, precision, recall, roots,
# specificity). _cells flattens them. The legal cell names come from metrics._cell itself, so they
# cannot drift; a name outside them fails closed, and a name merely absent (a zero count) reads 0.
CELL_NAMES = tuple(sorted({_cell(lab, o) for lab in ("bad", "good") for o in OUTCOMES}))
RATE_KEYS = ("recall", "specificity", "precision", "coverage")
ABSTAIN_KEYS = ("FN_abstain", "abstain")


class AgentScoreError(RuntimeError):
    """A fail-closed condition. Never a warning."""


# --------------------------------------------------------------------------- rows

def _row(record: Any) -> dict[str, Any]:
    """One rung row from a persisted summary record (or None), in metrics.row_from_finding's shape.

    D-008: a missing summary is an abstention, never "not vulnerable"; the ordinal score is the
    confidence if vulnerable, else 1 - confidence."""
    if not record:
        return {"outcome": "abstain", "score": None, "verdict": None}
    v = record["summary"]["verdict"]
    vulnerable = bool(v["vulnerable"])
    conf = float(v.get("confidence") or 0.0)
    return {
        "outcome": "flagged" if vulnerable else "clear",
        "score": round(conf if vulnerable else 1.0 - conf, 6),
        "verdict": {"mechanism": v["mechanism"], "region": v["region"],
                    "access": v["access"], "direction": v["direction"],
                    "vulnerable": vulnerable, "confidence": conf},
    }


def _stem(sha: str, addr: str) -> str:
    """The summary/prompt file stem analysis.analyze_one.stem produces: <sha[:12]>_<addr>.
    Duplicated rather than imported, so scoring never loads a provider module (see the note above);
    a test pins it to the real function."""
    return f"{sha[:12]}_{addr}"


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def walk_rows(run_dir: Path, roots: list[str]) -> dict[str, dict[str, Any]]:
    """Rows from a run dir's summaries.json ({addr: record or null}) -- the shape a fixed walk and
    an agent run both write."""
    doc = _read_json(Path(run_dir) / "summaries.json")
    missing = [a for a in roots if a not in doc]
    if missing:
        raise AgentScoreError(f"{run_dir}: roots missing from summaries.json: {missing[:3]}")
    return {a: _row(doc[a]) for a in roots}


def baseline_rows(run_dir: Path, sha: str, roots: list[str]) -> dict[str, dict[str, Any]]:
    """R4 rows: the per-function no-context summaries `walk --with-baseline` wrote (D-030)."""
    out: dict[str, dict[str, Any]] = {}
    for a in roots:
        f = Path(run_dir) / "baseline" / "summaries" / f"{_stem(sha, a)}.json"
        if not f.is_file():
            raise AgentScoreError(f"no R4 row for {a}: {f}")
        out[a] = _row(_read_json(f).get("record"))
    return out


# --------------------------------------------------------------------------- rung docs

def _identity(run_dir: Path, keys: tuple[str, ...]) -> dict[str, Any]:
    for name in ("walk.json", "agent.json"):
        f = Path(run_dir) / name
        if f.is_file():
            d = _read_json(f)
            return {k: d.get(k) for k in keys if k in d}
    raise AgentScoreError(f"{run_dir}: neither walk.json nor agent.json")


def rung_doc(rung: str, *, cases: dict[str, dict[str, Any]], definition: str) -> dict[str, Any]:
    """A D-030 rung document: programs[sha][addr] = row. `cases` maps case_id -> {sha, rows, identity}."""
    programs = {c["sha"]: c["rows"] for c in cases.values()}
    if len(programs) != len(cases):
        raise AgentScoreError(f"{rung}: two cases share a binary sha256")
    ids = {json.dumps(c["identity"], sort_keys=True) for c in cases.values()}
    if len(ids) > 1:
        raise AgentScoreError(f"{rung}: runs differ in provider identity or prompt version ({len(ids)})")
    return {"rung": rung, "kind": "llm", "score_scale": "ordinal", "definition": definition,
            "identity": json.loads(ids.pop()) if ids else {}, "programs": programs}


def collect(agent_root: Path, walk_root: Path,
            cases: list[tuple[str, str, list[str]]]) -> dict[str, Any]:
    """Build the four rungs' case tables. `cases` is (case_id, sha, roots), roots numerically sorted."""
    out: dict[str, dict[str, dict[str, Any]]] = {r: {} for r in RUNGS}
    for case_id, sha, roots in cases:
        w = Path(walk_root) / case_id
        wid = _identity(w, ("provider", "prompt_version", "callee_context_version"))
        out["R5"][case_id] = {"sha": sha, "rows": walk_rows(w, roots), "identity": wid}
        out["R4"][case_id] = {"sha": sha, "rows": baseline_rows(w, sha, roots), "identity": wid}
        for rung, policy in (("A1", "scripted"), ("A2", "llm")):
            d = Path(agent_root) / policy / case_id
            aid = _identity(d, ("policy", "agent_prompt_version"))
            out[rung][case_id] = {"sha": sha, "rows": walk_rows(d, roots), "identity": aid}
    return out


# --------------------------------------------------------------------------- fail-closed

def check_floor(agent_root: Path, cases: list[tuple[str, str, list[str]]],
                tables: dict[str, Any]) -> dict[str, Any]:
    """Rule 1: a root whose agent gathered nothing must carry its R4 cell exactly. Rule 2: no root
    may exceed its metered cap."""
    zero: list[str] = []
    over: list[str] = []
    checked = 0
    for rung, policy in (("A1", "scripted"), ("A2", "llm")):
        for case_id, _sha, roots in cases:
            doc = _read_json(Path(agent_root) / policy / case_id / "agent.json")
            cap = int(doc["caps"]["max_tokens_per_root"])
            for a in roots:
                fn = doc["functions"][a]
                if int(fn["metered_tokens"]) > cap:
                    over.append(f"{rung} {case_id} {a}: {fn['metered_tokens']} > {cap}")
                if not fn["summaries_fetched"] and not fn["code_read"]:
                    checked += 1
                    got = tables[rung][case_id]["rows"][a]["outcome"]
                    want = tables["R4"][case_id]["rows"][a]["outcome"]
                    if got != want:
                        zero.append(f"{rung} {case_id} {a}: {got} != R4 {want}")
    if over:
        raise AgentScoreError(f"metered total over cap on {len(over)} roots, e.g. {over[0]}")
    if zero:
        raise AgentScoreError(f"zero-fetch roots differ from R4 on {len(zero)}, e.g. {zero[0]}")
    return {"zero_fetch_roots": checked, "zero_fetch_matched_r4": checked}


def check_no_provider() -> list[str]:
    """Rule 3 (D-008 amendment): scoring must not have a model behind it."""
    loaded = sorted(m for m in sys.modules if m.startswith("taintwalk.llm"))
    if loaded:
        raise AgentScoreError(f"provider modules loaded while scoring: {loaded}")
    return loaded


# --------------------------------------------------------------------------- process and cost

def _dist(xs: list[int]) -> dict[str, Any]:
    if not xs:
        return {"n": 0, "median": None, "p90": None, "max": None, "total": 0}
    s = sorted(xs)
    p90 = s[min(len(s) - 1, int(round(0.9 * (len(s) - 1))))]
    return {"n": len(s), "median": statistics.median(s), "p90": p90, "max": s[-1], "total": sum(s)}


def process_table(agent_root: Path, cases: list[tuple[str, str, list[str]]]) -> dict[str, Any]:
    """Mechanical tables from the transcripts: what the policies actually did, and what it cost.
    A 90%-zero-step agent is R4 with extra steps, and this is where that shows."""
    out: dict[str, Any] = {}
    for rung, policy in (("A1", "scripted"), ("A2", "llm")):
        steps: list[int] = []
        metered: list[int] = []
        fetched: list[int] = []
        reads: list[int] = []
        stops: dict[str, int] = {}
        abstained: dict[str, int] = {}
        invalid = repeated = zero = 0
        for case_id, _sha, roots in cases:
            doc = _read_json(Path(agent_root) / policy / case_id / "agent.json")
            for a in roots:
                f = doc["functions"][a]
                steps.append(int(f["steps"]))
                metered.append(int(f["metered_tokens"]))
                stops[f["stop"]] = stops.get(f["stop"], 0) + 1
                fetched.append(len(f["summaries_fetched"]))
                reads.append(len(f["code_read"]))
                invalid += int(f["invalid_actions"])
                repeated += int(f["repeated_actions"])
                zero += not f["summaries_fetched"] and not f["code_read"]
                if f.get("judge", "ok") != "ok":       # no verdict: name it (D-040 rule 4)
                    why = f.get("failure") or f.get("judge") or "unknown"
                    abstained[why] = abstained.get(why, 0) + 1
        out[rung] = {
            "policy": policy, "roots": len(steps),
            "steps": _dist(steps), "metered_tokens": _dist(metered),
            "summaries_fetched": _dist(fetched), "code_reads": _dist(reads),
            "stops": dict(sorted(stops.items())),
            "abstentions": dict(sorted(abstained.items())),
            "invalid_actions": invalid, "repeated_actions": repeated, "zero_fetch_roots": zero,
        }
    return out


# --------------------------------------------------------------------------- cost (as from an empty cache)

# walk_all.TOKENS_LINE, duplicated so the scorer never imports analysis/ code that may load llm.
LOG_TOKENS = re.compile(r"^tokens \(this run\)\s*:\s*in (\d+)\s+out (\d+)\s+model time ([\d.]+) s", re.M)


def cache_dir() -> Path:
    """The llm layer's disk cache, from config/providers.yaml (cache_dir)."""
    import yaml
    cfg = yaml.safe_load((REPO_ROOT / "config" / "providers.yaml").read_text(encoding="utf-8"))
    return REPO_ROOT / cfg["cache_dir"]


def _entry_tokens(cache: Path, key: str) -> int:
    """Input + output tokens of the live call that wrote this cache entry. A cache hit replays the
    entry, so this is the call's cost as if the cache had been empty."""
    f = Path(cache) / key[:2] / f"{key}.json"
    if not f.is_file():
        raise AgentScoreError(f"cost: no cache entry for {key[:12]} ({f})")
    u = _read_json(f).get("usage") or {}
    return int(u.get("input_tokens") or 0) + int(u.get("output_tokens") or 0)


def _system_text(system: Path, want_sha: str) -> str:
    """The system prompt text whose sha256 the prompt file recorded (trailing newline tolerated)."""
    import hashlib
    raw = Path(system).read_text(encoding="utf-8")
    for cand in (raw, raw.rstrip("\n")):
        if hashlib.sha256(cand.encode("utf-8")).hexdigest() == want_sha:
            return cand
    raise AgentScoreError(f"cost: {system} does not match the prompt's system_sha256")


def _metered(prompt_doc: dict[str, Any], system_text: str, ratio: float) -> int:
    """analysis.agent.meter over a persisted prompt file, re-implemented so no llm module loads."""
    replies = sum(len((a.get("text") if isinstance(a, dict) else "") or "")
                  for a in prompt_doc.get("attempts", []))
    return math.ceil((len(system_text) + 1 + len(prompt_doc["user"]) + replies) / ratio)


def juliet_r4(walk_root: Path):
    """R4 files for a Juliet root: the Phase 8 walk's --with-baseline rows (D-030)."""
    def files(case_id: str, sha: str, addr: str) -> tuple[Path, Path, Path]:
        b = Path(walk_root) / case_id / "baseline"
        s = _stem(sha, addr)
        return b / "summaries" / f"{s}.json", b / "prompts" / f"{s}.json", b / "system.txt"
    return files


def real_r4(r4_dir: Path):
    """R4 files for a real-code root: Phase 9's analyze-one run at the roots (D-038)."""
    def files(case_id: str, sha: str, addr: str) -> tuple[Path, Path, Path]:
        s = _stem(sha, addr)
        r = Path(r4_dir)
        return r / "summaries" / f"{s}.json", r / "prompts" / f"{s}.json", r / "system.txt"
    return files


def cost_table(agent_root: Path, cases: list[tuple[str, str, list[str]]], r4_files,
               cache: Path | None = None) -> dict[str, Any]:
    """Per root, per policy: real tokens (from the cache entries of every call the root made) and
    metered tokens, in full and beyond R4 (minus the root's own R4 call). Model time is not in the
    cache, so it is summed per run from the program logs' tokens lines. Fails closed on a missing
    key, entry or R4 file, and on an A1 zero-fetch root whose cost beyond R4 is not exactly 0."""
    cache = Path(cache) if cache is not None else cache_dir()
    out: dict[str, Any] = {}
    for rung, policy in POLICIES:
        cols: dict[str, list[int]] = {"real_full": [], "real_beyond": [],
                                      "metered_full": [], "metered_beyond": []}
        model_s = 0.0
        logs = 0
        zero_checked = 0
        for case_id, sha, roots in cases:
            d = Path(agent_root) / policy / case_id
            doc = _read_json(d / "agent.json")
            ratio = float(doc["caps"]["token_chars_ratio"])
            for a in roots:
                f = doc["functions"][a]
                keys = f.get("call_keys")
                if keys is None:
                    raise AgentScoreError(f"cost: {rung} {case_id} {a}: agent.json has no call_keys")
                row_p, prompt_p, sys_p = r4_files(case_id, sha, a)
                r4_key = _read_json(row_p).get("cache_key")
                if not r4_key:
                    raise AgentScoreError(f"cost: no R4 cache_key in {row_p}")
                pdoc = _read_json(prompt_p)
                r4_real = _entry_tokens(cache, r4_key)
                r4_met = _metered(pdoc, _system_text(sys_p, pdoc["system_sha256"]), ratio)
                real = sum(_entry_tokens(cache, k) for k in keys)
                met = int(f["metered_tokens"])
                cols["real_full"].append(real)
                cols["real_beyond"].append(real - r4_real)
                cols["metered_full"].append(met)
                cols["metered_beyond"].append(met - r4_met)
                if (policy == "scripted" and not f["summaries_fetched"] and not f["code_read"]
                        and f.get("judge") != "agent:budget"):
                    zero_checked += 1
                    if real != r4_real or met != r4_met:
                        raise AgentScoreError(
                            f"cost: A1 zero-fetch root {case_id} {a} costs more than R4 "
                            f"(real {real} vs {r4_real}, metered {met} vs {r4_met})")
            log = Path(agent_root) / policy / "logs" / f"{case_id}.log"
            m = LOG_TOKENS.search(log.read_text(encoding="utf-8")) if log.is_file() else None
            if m:
                logs += 1
                model_s += float(m.group(3))
        out[rung] = {"policy": policy, "roots": len(cols["real_full"]),
                     **{k: _dist(v) for k, v in cols.items()},
                     "model_s_logs": round(model_s, 1), "programs_with_tokens_line": logs,
                     "programs": len(cases), "a1_zero_fetch_checked": zero_checked}
    return out


def render_cost(cost: dict[str, Any]) -> list[str]:
    L = ["", "### Cost per root (as from an empty cache; beyond R4 = minus the root's own R4 call)", "",
         "| Rung | Roots | Real tokens med/p90/max | Real beyond R4 | Metered med/p90/max | "
         "Metered beyond R4 | Model time, s (logs) |",
         "|---|---|---|---|---|---|---|"]
    for r in ("A1", "A2"):
        c = cost[r]
        L.append(f"| {r} | {c['roots']} | {_d(c['real_full'])} | {_d(c['real_beyond'])} | "
                 f"{_d(c['metered_full'])} | {_d(c['metered_beyond'])} | {c['model_s_logs']} |")
    a1, a2 = cost["A1"], cost["A2"]
    L += ["", f"Real tokens are read from the cache entry of every call a root made, so a cache hit "
              f"costs what its live call cost. Model time is not in the cache: it is the sum of the "
              f"programs' `tokens (this run)` lines ({a2['programs_with_tokens_line']} of "
              f"{a2['programs']} A2 programs), so a resumed program counts only its last process. "
              f"A1 zero-fetch roots costing exactly R4: {a1['a1_zero_fetch_checked']}."]
    return L


# --------------------------------------------------------------------------- cells

def _cells(scored: dict[str, Any], rung: str) -> dict[str, Any]:
    """The pooled primary confusion dict, flattened: its rates plus one count per D-008 cell name.
    Validated once so a shape surprise names itself."""
    strata = scored.get("strata") or {}
    if "pooled" not in strata:
        raise AgentScoreError(f"{rung}: no pooled stratum; strata are {sorted(strata)}")
    c = strata["pooled"].get("primary")
    if not isinstance(c, dict):
        raise AgentScoreError(f"{rung}: pooled stratum has no primary confusion dict")
    counts = c.get("cells")
    if not isinstance(counts, dict):
        raise AgentScoreError(
            f"{rung}: primary confusion has no cells dict; its actual keys are {sorted(c)}")
    unknown = sorted(set(counts) - set(CELL_NAMES))
    if unknown:
        raise AgentScoreError(
            f"{rung}: unknown cell names {unknown}; expected a subset of {list(CELL_NAMES)}")
    flat = {k: v for k, v in c.items() if k != "cells"}
    flat.update({k: int(counts.get(k) or 0) for k in CELL_NAMES})
    return flat


def _abstain(c: dict[str, Any]) -> int:
    return sum(int(c.get(k) or 0) for k in ABSTAIN_KEYS if k in c)


# --------------------------------------------------------------------------- real code (D-040)

POLICIES = (("A1", "scripted"), ("A2", "llm"))
GROUPS = ("all", "with_callees", "no_callee")


def real_inputs(manifest: dict[str, Any], programs_dir: Path, r4_dir: Path, walk_root: Path
                ) -> tuple[list[dict[str, Any]], dict[str, dict[tuple[str, str], str]], dict[tuple[str, str], int]]:
    """The 24 roots, their R4 and R5 outcomes, and each root's walk callee-block size, all through
    real_score's loaders (the Phase 9 gate's code path), so 9b cannot read a different row."""
    try:
        roots, _progs = load_roots(manifest, Path(programs_dir))
        r4, _ = r4_doc(Path(r4_dir), roots)
        r5, _, ctx = r5_doc(Path(walk_root), roots)
    except RealScoreError as e:
        raise AgentScoreError(f"real: {e}") from e
    outcomes: dict[str, dict[tuple[str, str], str]] = {"R4": {}, "R5": {}}
    for r in roots:
        sha, addr = r["binary_sha256"], r["addr"]
        outcomes["R4"][(sha, addr)] = r4["programs"][sha][addr]["outcome"]
        outcomes["R5"][(sha, addr)] = r5["programs"][sha][addr]["outcome"]
    return roots, outcomes, ctx


def real_cases(roots: list[dict[str, Any]]) -> list[tuple[str, str, list[str]]]:
    """(case_id, sha, roots) per binary. One binary can hold the post root of one pair and the pre
    root of another, so a case may carry two roots; they are numerically sorted, as in agent_sets."""
    by: dict[str, tuple[str, list[str]]] = {}
    for r in roots:
        sha, addrs = by.setdefault(r["case_id"], (r["binary_sha256"], []))
        if sha != r["binary_sha256"]:
            raise AgentScoreError(f"real: {r['case_id']} maps to two binaries")
        addrs.append(r["addr"])
    return [(c, sha, sorted(set(a), key=lambda x: int(x, 16))) for c, (sha, a) in sorted(by.items())]


def real_pairs(roots: list[dict[str, Any]], outcomes: dict[str, dict[tuple[str, str], str]],
               ctx: dict[tuple[str, str], int]) -> dict[str, Any]:
    """Pure: per-rung root outcomes -> D-008 cells and D-040 pair outcomes. Rule 4 holds here too:
    every root needs a row in every rung, and every pair both of its sides."""
    missing = [k for k in RUNGS if k not in outcomes]
    if missing:
        raise AgentScoreError(f"real: rungs missing: {missing}")
    rows: dict[str, list[dict[str, Any]]] = {k: [] for k in RUNGS}
    sides: dict[str, dict[str, dict[str, Any]]] = {}
    for r in roots:
        key = (r["binary_sha256"], r["addr"])
        where = f"{r['pair_id']} {r['side']} {r['case_id']} {r['addr']}"
        o: dict[str, str] = {}
        for k in RUNGS:
            if key not in outcomes[k]:
                raise AgentScoreError(f"real {k}: no row for {where}")
            if outcomes[k][key] not in OUTCOMES:
                raise AgentScoreError(f"real {k}: invalid outcome {outcomes[k][key]!r} for {where}")
            o[k] = outcomes[k][key]
            rows[k].append({"label": r["label"], "outcome": o[k], "cell": _cell(r["label"], o[k])})
        if key not in ctx:
            raise AgentScoreError(f"real: no walk context size for {where}")
        sides.setdefault(r["pair_id"], {})[r["side"]] = {**r, "outcomes": o, "context_chars": ctx[key]}

    pairs: list[dict[str, Any]] = []
    for pid in sorted(sides):
        if set(sides[pid]) != {"pre", "post"}:
            raise AgentScoreError(f"real: pair {pid} has sides {sorted(sides[pid])}")
        pre, post = sides[pid]["pre"], sides[pid]["post"]
        pairs.append({
            "pair_id": pid, "cve": pre["cve"], "project": pre["project"], "function": pre["function"],
            "no_callee": pre["context_chars"] == 0 and post["context_chars"] == 0,
            "pre": pre["outcomes"], "post": post["outcomes"],
            "outcomes": {k: _pair_outcome(pre["outcomes"][k], post["outcomes"][k]) for k in RUNGS},
        })
    groups = {"all": pairs, "with_callees": [p for p in pairs if not p["no_callee"]],
              "no_callee": [p for p in pairs if p["no_callee"]]}
    return {
        "pairs": len(pairs), "roots": len(roots),
        "cells": {k: _cells({"strata": {"pooled": {"primary": confusion(rows[k])}}}, f"real {k}")
                  for k in RUNGS},
        "pair_outcomes": {g: {k: _pair_counts(ps, k) for k in RUNGS} for g, ps in groups.items()},
        "pairs_detail": pairs,
    }


def _pair_outcome(pre: str, post: str) -> str:
    """real_score.pair_outcome, with its RealScoreError turned into this module's fail-closed error."""
    try:
        return pair_outcome(pre, post)
    except RealScoreError as e:
        raise AgentScoreError(f"real: {e}") from e


def score_real(agent_root: Path, *, manifest: dict[str, Any], programs_dir: Path, r4_dir: Path,
               walk_root: Path) -> dict[str, Any]:
    """A1 and A2 at the Phase 9 roots, beside Phase 9's own R4 and R5, under rules 1, 2 and 4."""
    roots, outcomes, ctx = real_inputs(manifest, programs_dir, r4_dir, walk_root)
    cases = real_cases(roots)
    tables: dict[str, dict[str, Any]] = {
        "R4": {c: {"rows": {a: {"outcome": outcomes["R4"][(sha, a)]} for a in rs}} for c, sha, rs in cases}}
    for rung, policy in POLICIES:
        tables[rung] = {}
        outcomes[rung] = {}
        ids: set[str] = set()
        for c, sha, rs in cases:
            d = Path(agent_root) / policy / c
            rows = walk_rows(d, rs)
            ids.add(json.dumps(_identity(d, ("policy", "agent_prompt_version")), sort_keys=True))
            tables[rung][c] = {"rows": rows}
            for a in rs:
                outcomes[rung][(sha, a)] = rows[a]["outcome"]
        if len(ids) > 1:
            raise AgentScoreError(f"real {rung}: runs differ in policy or agent prompt version ({len(ids)})")
    floor = check_floor(agent_root, cases, tables)
    return {**real_pairs(roots, outcomes, ctx), "floor": floor,
            "process": process_table(agent_root, cases),
            "cost": cost_table(agent_root, cases, real_r4(r4_dir))}


# --------------------------------------------------------------------------- render

def _f(x: Any) -> str:
    """A rate as 3 decimals. metrics carries rates as Wilson dicts ({"value": ...}, as real_score
    reads them), so the point estimate is unwrapped; a bare number passes through."""
    if isinstance(x, dict):
        x = x.get("value")
    return "\u2014" if x is None else (f"{x:.3f}" if isinstance(x, (int, float)) else str(x))


def _cell_rows(cells: dict[str, dict[str, Any]]) -> list[str]:
    return [f"| {r} | {c.get('TP', 0)} | {c.get('FN', 0)} | {c.get('FP', 0)} | "
            f"{c.get('TN', 0)} | {_abstain(c)} | "
            + " | ".join(_f(c.get(k)) for k in RATE_KEYS) + " |"
            for r, c in ((r, cells[r]) for r in RUNGS)]


CELL_HEADER = ["| Rung | TP | FN | FP | TN | Abstain | Recall | Specificity | Precision | Coverage |",
               "|---|---|---|---|---|---|---|---|---|---|"]


def render_real(rd: dict[str, Any]) -> list[str]:
    """The real-code subsection: cells, D-040 pair outcomes by group, and every pair."""
    L = ["", f"### Real code: {rd['pairs']} vulnerable/patched pairs, {rd['roots']} roots (D-040)", "",
         "The same judge and rungs at the Phase 9 roots. A pair is correct only if its pre-fix root "
         "is flagged and its post-fix root is clear. Descriptive; no tests (D-042).", "",
         *CELL_HEADER, *_cell_rows(rd["cells"]), "",
         "| Group | Rung | Pairs | Pair-correct | Both vulnerable | Both clear | Reversed | Abstained |",
         "|---|---|---|---|---|---|---|---|"]
    for g in GROUPS:
        for r in RUNGS:
            po = rd["pair_outcomes"][g][r]
            L.append(f"| {g} | {r} | {po['pairs']} | "
                     + " | ".join(str(po[o]) for o in PAIR_OUTCOMES) + " |")
    L += ["", "Pre/post outcome per rung: F flagged, C clear, A abstained.", "",
          "| Pair | CVE | Project | Function | No callee | " + " | ".join(RUNGS) + " |",
          "|---|---|---|---|---|" + "---|" * len(RUNGS)]
    for p in rd["pairs_detail"]:
        L.append(f"| {p['pair_id']} | {p['cve']} | {p['project']} | {p['function']} | "
                 f"{'yes' if p['no_callee'] else ''} | "
                 + " | ".join(f"{SHORT[p['pre'][r]]}/{SHORT[p['post'][r]]}" for r in RUNGS) + " |")
    L += ["", f"Real-code floor check: {rd['floor']['zero_fetch_roots']} zero-fetch roots, all equal "
              f"to their R4 cell. Caps held on every root."]
    if rd.get("cost"):
        L += render_cost(rd["cost"])
    return L


def _d(d: dict[str, Any]) -> str:
    return f"{d['median']}/{d['p90']}/{d['max']}"


def render(doc: dict[str, Any]) -> str:
    L = [BEGIN, "", "## Phase 10: agentic evidence gathering (D-042)", "",
         f"Status: {doc['status']}", "",
         "One judge for every rung; only the evidence block differs. "
         "R4 no evidence, A1 scripted reads, A2 agent-chosen reads, R5 the fixed walk.", "",
         *CELL_HEADER, *_cell_rows(doc["cells"])]

    t = doc["tests"]
    holm_note = "" if t["holm_applied"] else "; NOT APPLIED, family incomplete"
    L += ["", f"### Pre-registered tests ({t['family']}, Holm at {t['alpha']}{holm_note})", "",
          "| Test | Label | n | A right | B right | A only | B only | p | p (Holm) | Reject |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for name in sorted(t["tests"]):
        v = t["tests"][name]
        L.append(f"| {v['a']} vs {v['b']} | {v['label']} | {v['n']} | {v['a_right']} | "
                 f"{v['b_right']} | {v['a_only']} | {v['b_only']} | {v['p']:.4f} | "
                 f"{v.get('p_holm', '\u2014')} | {'yes' if v.get('reject') else 'no'} |")

    L += ["", "### Process and cost (from the transcripts)", "",
          "| Rung | Roots | Steps med/p90/max | Metered med/p90/max | Summaries med | "
          "Code reads med | Zero-fetch | Invalid | Repeated |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in ("A1", "A2"):
        p = doc["process"][r]
        L.append(f"| {r} | {p['roots']} | {_d(p['steps'])} | {_d(p['metered_tokens'])} | "
                 f"{p['summaries_fetched']['median']} | {p['code_reads']['median']} | "
                 f"{p['zero_fetch_roots']} | {p['invalid_actions']} | {p['repeated_actions']} |")
    for r in ("A1", "A2"):
        p = doc["process"][r]
        L.append(f"\n{r} stop reasons: " + ", ".join(f"{k} {v}" for k, v in p["stops"].items()))
        ab = p.get("abstentions") or {}
        L.append(f"\n{r} abstentions by name: "
                 + (", ".join(f"{k} {v}" for k, v in ab.items()) if ab else "none"))

    L += ["", f"Floor check: {doc['floor']['zero_fetch_roots']} zero-fetch roots, all equal to "
              f"their R4 cell. Caps held on every root."]
    if doc.get("cost"):
        L += render_cost(doc["cost"])
    if doc.get("real"):
        L += render_real(doc["real"])
    L += ["", END, ""]
    return "\n".join(L)


def splice(md: Path, section: str) -> None:
    """Replace the one phase10 section, or append it. Idempotent: re-splicing the same section
    leaves the file byte-identical, which the gate's second run depends on. The section is stripped
    of its own surrounding blank lines so the replace and append paths end the same way -- without
    that, each replace kept the newline that followed END and the file grew a blank line per run."""
    md = Path(md)
    text = md.read_text(encoding="utf-8") if md.is_file() else ""
    body = section.strip("\n")
    if BEGIN in text and END in text:
        head, rest = text.split(BEGIN, 1)
        text = head + body + rest.split(END, 1)[1]
    else:
        text = text.rstrip("\n") + "\n\n" + body + "\n"
    md.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------- main

def score(agent_root: Path, walk_root: Path, cases: list[tuple[str, str, list[str]]], *,
          status: str, real: dict[str, Path] | None = None) -> dict[str, Any]:
    """`real`, when given, holds the paths score_real needs: agent_root, manifest, programs, r4, walk."""
    check_no_provider()
    cfg = load_config()
    manifest_rel = cfg.get("corpus", {}).get("manifest", "corpus/manifest.json")
    manifest = _read_json(REPO_ROOT / manifest_rel)
    out_dir = REPO_ROOT / cfg["extract"]["out_dir"]

    tables = collect(agent_root, walk_root, cases)
    floor = check_floor(agent_root, cases, tables)

    defs = {"R4": "per-function LLM, no callee context (D-030)",
            "A1": "scripted agent: every direct callee's no-context summary (D-042)",
            "A2": "agent policy: model-chosen reads (D-042)",
            "R5": "TaintWalk fixed bottom-up walk (D-030)"}
    scored = {r: score_rung(rung_doc(r, cases=tables[r], definition=defs[r]),
                            manifest=manifest, labels_dir=out_dir / "labels",
                            programs_dir=out_dir / "programs")
              for r in RUNGS}

    keys = {r: {(x["case_id"], x["addr"]) for x in scored[r]["roots"]} for r in RUNGS}
    if len({frozenset(v) for v in keys.values()}) != 1:       # rule 4
        raise AgentScoreError(f"rungs hold different roots: {{{', '.join(f'{r}: {len(v)}' for r, v in keys.items())}}}")

    tests = preregistered_tests({r: scored[r]["roots"] for r in RUNGS},
                                comparisons=P10_COMPARISONS)
    real_doc = None
    if real:
        real_doc = score_real(real["agent_root"], manifest=_read_json(real["manifest"]),
                              programs_dir=real["programs"], r4_dir=real["r4"], walk_root=real["walk"])
    return {"score_version": SCORE_VERSION, "rules": "D-042", "status": status, "real": real_doc,
            "roots": len(next(iter(keys.values()))),
            "cells": {r: _cells(scored[r], r) for r in RUNGS},
            "tests": tests, "process": process_table(agent_root, cases), "floor": floor,
            "cost": cost_table(agent_root, cases, juliet_r4(walk_root)),
            "rungs": {r: {"definition": defs[r], "identity": scored[r]["identity"]} for r in RUNGS}}


def load_cases(programs_txt: Path) -> list[tuple[str, str, list[str]]]:
    """(case_id, sha256, roots) from an agent_sets programs.txt line: '<path> 0xa,0xb'."""
    out: list[tuple[str, str, list[str]]] = []
    for raw in Path(programs_txt).read_text(encoding="utf-8").splitlines():
        parts = raw.split()
        if not parts or parts[0].startswith("#"):
            continue
        p = Path(parts[0])
        p = p if p.is_absolute() else REPO_ROOT / p
        sha = _read_json(p)["binary"]["sha256"]
        out.append((p.stem, sha, parts[1].split(",") if len(parts) > 1 else []))
    if not out:
        raise AgentScoreError(f"no programs in {programs_txt}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taintwalk.eval.agent_score")
    ap.add_argument("--agent-root", type=Path, default=None,
                    help="root holding <policy>/<case_id>/ run dirs "
                         "(default: runs/p10-scored, or runs/p10-dev with --dev)")
    ap.add_argument("--walk-root", type=Path, default=Path("runs/p8-local"),
                    help="the fixed walk's run dirs, which also hold the R4 baseline rows")
    ap.add_argument("--programs", type=Path, default=None,
                    help="an agent_sets programs.txt (default: runs/p10/scored.programs.txt, "
                         "or runs/p10/dev.programs.txt with --dev)")
    ap.add_argument("--out", type=Path, default=None, help="default: <agent-root>/eval")
    ap.add_argument("--results-md", type=Path, default=None)
    ap.add_argument("--dev", action="store_true",
                    help="development slice: never reportable, never spliced (D-028, D-042)")
    ap.add_argument("--real-agent-root", type=Path, default=Path("runs/p10-real"),
                    help="root holding <policy>/<case_id>/ run dirs for the Phase 9 programs")
    ap.add_argument("--real-programs", type=Path, default=Path("runs/p9-real/programs"))
    ap.add_argument("--real-r4", type=Path, default=Path("runs/p9-real/r4"))
    ap.add_argument("--real-walk", type=Path, default=Path("runs/p9-real/walk"))
    ap.add_argument("--real-manifest", type=Path, default=None,
                    help="default: config real.manifest")
    ap.add_argument("--no-real", action="store_true",
                    help="Juliet only (always so with --dev: the dev slice has no real code)")
    args = ap.parse_args(argv)

    agent_root = args.agent_root or Path("runs/p10-dev" if args.dev else "runs/p10-scored")
    programs = args.programs or Path(
        "runs/p10/dev.programs.txt" if args.dev else "runs/p10/scored.programs.txt")
    status = ("development slice, not reportable (D-028)" if args.dev
              else "scored set, local model only (D-034)")
    try:
        cases = load_cases(programs)
        real = None
        if not (args.dev or args.no_real):
            real = {"agent_root": args.real_agent_root,
                    "manifest": args.real_manifest or REPO_ROOT / load_config()["real"]["manifest"],
                    "programs": args.real_programs, "r4": args.real_r4, "walk": args.real_walk}
        doc = score(agent_root, args.walk_root, cases, status=status, real=real)
    except (AgentScoreError, OSError, KeyError, ValueError) as e:
        print(f"AGENT EVAL FAIL: {type(e).__name__}: {e}")
        return 1

    out = Path(args.out or (agent_root / "eval"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "agent.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                    encoding="utf-8")
    section = render(doc)
    (out / "results-p10.md").write_text(section, encoding="utf-8")
    if args.results_md and not args.dev:
        splice(args.results_md, section)
    t = doc["tests"]
    rd = doc["real"]
    real_note = f"; real {rd['pairs']} pairs, {rd['roots']} roots" if rd else "; real not scored"
    print(f"AGENT EVAL OK: {doc['roots']} roots, rungs {' '.join(RUNGS)}, "
          f"{len(t['tests'])} tests, Holm {'applied' if t['holm_applied'] else 'NOT applied'}"
          f"{real_note} -> {out / 'agent.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())