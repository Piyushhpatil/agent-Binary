"""Error-analysis tooling for Phase 8 (D-032, mini-step 16).

Hand coding needs a fixed, reproducible sample and everything the model saw; the automated measures read
persisted files only:
- error_sample(): a seeded sample (ERROR_SAMPLE_SEED, fixed before any cloud number existed) of up to
  SAMPLE_SIZE false-positive roots (cell FP) and false-negative roots (cell FN) of one rung. Bad roots that
  abstained (FN_abstain) are not hand-coded; abstention_kinds() counts why rows abstained.
- worksheet(): one Markdown section per sampled root: the pre-registered codebook, the verdict and reason,
  the unguarded sinks, the root's raw pseudo-C, and the callee block the walk showed the model.
- parroting(): how often a stated reason shares a run of PARROT_MIN_WORDS or more consecutive words with a
  few-shot reason (D-025: the rejected 7B model pasted few-shot sentences into unrelated functions).
- literal_shortcut(): per label, outcomes at roots whose own pseudo-C holds a sanitizer error message
  (D-018) versus roots whose code does not. The message list comes from a label-free survey of the walked
  functions (Phase 8 mini-step 16a).
"""
from __future__ import annotations

import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

from taintwalk.analysis.callgraph import addr_key
from taintwalk.analysis.prompts import CALLEE_HEADER, examples
from taintwalk.eval.score import discover_runs

ERROR_SAMPLE_SEED = 20260930
SAMPLE_SIZE = 20
PARROT_MIN_WORDS = 8
SANITIZER_LITERAL = re.compile(
    r'"(?:ERROR: Array index is|data value is too (?:large|small) to|'
    r'Input is less than the length of the source string)[^"]*"'
)
CODEBOOK = {
    "FP": ("ignored guard", "context-induced: a callee summary said vulnerable", "ignored constant argument",
           "decompiler artifact", "invented sink or source", "other"),
    "FN": ("missed sink", "hallucinated guard", "context-induced: a callee summary said safe",
           "decompiler artifact", "other"),
}
ARMS = ("walk", "baseline")


class ErrorAnalysisError(RuntimeError):
    """A run dir or a program does not line up with the scored roots."""


# ---- reading run dirs --------------------------------------------------------------------------

def _walk_json(run_dir: Path) -> dict[str, Any]:
    return json.loads((Path(run_dir) / "walk.json").read_text(encoding="utf-8"))


def run_dirs_by_sha(root: Path) -> dict[str, Path]:
    return {_walk_json(d)["binary_sha256"]: d for d in discover_runs(Path(root))}


def _arm_record(run_dir: Path, walk: dict[str, Any], summaries: dict[str, Any], addr: str,
                arm: str) -> dict[str, Any] | None:
    """The record one arm produced for a function: the no-context row where one exists, else the walk row
    (a function with no callee block had the same prompt in both arms)."""
    if arm not in ARMS:
        raise ErrorAnalysisError(f"unknown arm {arm!r}")
    if arm == "baseline" and addr in (walk.get("baseline") or {}):
        p = Path(run_dir) / "baseline" / "summaries" / f"{walk['binary_sha256'][:12]}_{addr}.json"
        if not p.exists():
            raise ErrorAnalysisError(f"{p} is missing")
        return json.loads(p.read_text(encoding="utf-8")).get("record")
    return summaries.get(addr)


def arm_reasons(root: Path, arm: str) -> list[str]:
    """The stated reason of every answered row of one arm, over every walk run dir at or under root."""
    out: list[str] = []
    for d in discover_runs(Path(root)):
        walk = _walk_json(d)
        summaries = json.loads((d / "summaries.json").read_text(encoding="utf-8"))
        for a in sorted(walk["functions"], key=addr_key):
            rec = _arm_record(d, walk, summaries, a, arm)
            if rec is not None:
                out.append(rec["summary"]["verdict"]["reason"])
    return out


def abstention_kinds(root: Path, arm: str) -> dict[str, int]:
    """Why rows of one arm have no summary, counted by failure kind (every walked function)."""
    if arm not in ARMS:
        raise ErrorAnalysisError(f"unknown arm {arm!r}")
    c: Counter = Counter()
    for d in discover_runs(Path(root)):
        walk = _walk_json(d)
        base = walk.get("baseline") or {}
        for a, fn in walk["functions"].items():
            e = base[a] if arm == "baseline" and a in base else fn
            if e["status"] != "ok":
                c[e.get("failure") or e["status"]] += 1
    return dict(sorted(c.items()))


# ---- sample and worksheet --------------------------------------------------------------------------

def _order(r: dict[str, Any]) -> tuple[str, int]:
    return r["case_id"], addr_key(r["addr"])


def error_sample(score: dict[str, Any], *, seed: int = ERROR_SAMPLE_SEED,
                 n: int = SAMPLE_SIZE) -> dict[str, list[dict[str, Any]]]:
    """Up to n FP roots and n FN roots, seeded; all of them when there are fewer. Sorted for reading."""
    rng = random.Random(seed)
    out: dict[str, list[dict[str, Any]]] = {}
    for cell in ("FP", "FN"):
        pool = sorted((r for r in score["roots"] if r["cell"] == cell), key=_order)
        picked = pool if len(pool) <= n else rng.sample(pool, n)
        out[cell] = sorted(picked, key=_order)
    return out


def _callee_block(run_dir: Path, sha: str, addr: str) -> str:
    p = Path(run_dir) / "prompts" / f"{sha[:12]}_{addr}.json"
    if not p.exists():
        return ""
    user = json.loads(p.read_text(encoding="utf-8"))["user"]
    i = user.find(CALLEE_HEADER)
    return user[i:].strip() if i >= 0 else ""


def worksheet(score: dict[str, Any], root: Path, *, arm: str, programs_dir: Path,
              seed: int = ERROR_SAMPLE_SEED, n: int = SAMPLE_SIZE) -> tuple[str, dict[str, Any]]:
    """The hand-coding worksheet for one rung, and its sample index."""
    sample = error_sample(score, seed=seed, n=n)
    dirs = run_dirs_by_sha(root)
    rung = score.get("rung", "?")
    lines = [f"# Error-analysis worksheet: {rung} ({arm} arm)", "",
             f"Seeded sample (seed {seed}): up to {n} false positives and {n} false negatives at path roots. "
             "Give every root exactly one codebook entry and a one-line note.", "",
             "## Codebook (pre-registered, D-032)", ""]
    lines += [f"- {cell}: " + "; ".join(f"`{c}`" for c in codes) for cell, codes in CODEBOOK.items()]
    index: dict[str, Any] = {"rung": rung, "arm": arm, "seed": seed, "size": n, "FP": [], "FN": []}
    progs: dict[str, dict[str, Any]] = {}
    for cell in ("FP", "FN"):
        total = sum(r["cell"] == cell for r in score["roots"])
        lines += ["", f"## {cell}: {len(sample[cell])} of {total} roots"]
        for i, r in enumerate(sample[cell], 1):
            d = dirs.get(r["binary_sha256"])
            if d is None:
                raise ErrorAnalysisError(f"{r['case_id']}: no walk run dir for binary {r['binary_sha256'][:12]}")
            walk = _walk_json(d)
            summaries = json.loads((d / "summaries.json").read_text(encoding="utf-8"))
            rec = _arm_record(d, walk, summaries, r["addr"], arm)
            if r["case_id"] not in progs:
                prog = json.loads((Path(programs_dir) / f"{r['case_id']}.json").read_text(encoding="utf-8"))
                progs[r["case_id"]] = {f["addr"]: f for f in prog["functions"]}
            fn = progs[r["case_id"]].get(r["addr"])
            if fn is None:
                raise ErrorAnalysisError(f"{r['case_id']} {r['addr']}: not in program.json")
            lines += ["", f"### {cell}-{i:02d} {r['case_id']} {r['addr']} {fn.get('ghidra_name', '')}".rstrip(), "",
                      f"- class {r['cwe']}, flow {r['flow_variant']}, stratum {r['stratum']}, "
                      f"path members {len(r['members'])}"]
            if rec is None:
                lines.append("- no summary (abstained)")
            else:
                v = rec["summary"]["verdict"]
                sinks = [s for s in rec["summary"]["sinks"] if not s["guarded"]]
                lines += [f"- verdict: {v['mechanism']} / {v['region']} / {v['access']} / {v['direction']}; "
                          f"vulnerable {v['vulnerable']}; confidence {v['confidence']}",
                          f"- reason: {v['reason']}",
                          "- unguarded sinks: " + ("; ".join(
                              f"line {s['evidence_line']} {s['sink_kind']} {s['callee']}".rstrip() for s in sinks)
                              or "none")]
            lines += ["- code: ____   note: ____", "",
                      "Raw pseudo-C (the model saw it after zero-fill collapse and literal redaction):", "",
                      "```c", (fn.get("pseudo_c") or "").rstrip(), "```"]
            block = _callee_block(d, r["binary_sha256"], r["addr"]) if arm == "walk" else ""
            if block:
                lines += ["", "Callee block the walk showed the model:", "", "```", block, "```"]
            index[cell].append({"case_id": r["case_id"], "addr": r["addr"]})
    return "\n".join(lines) + "\n", index


# ---- automated measures ------------------------------------------------------------------------

def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def _shingles(words: list[str], k: int) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + k]) for i in range(len(words) - k + 1)}


def fewshot_reasons() -> list[str]:
    return [s.verdict.reason for _, _, s in examples()]


def parroting(reasons: list[str], shots: list[str] | None = None,
              min_words: int = PARROT_MIN_WORDS) -> dict[str, Any]:
    """Share of reasons that contain min_words or more consecutive words of any few-shot reason."""
    shot_grams: set[tuple[str, ...]] = set()
    for s in (fewshot_reasons() if shots is None else shots):
        shot_grams |= _shingles(_words(s), min_words)
    hits = [r for r in reasons if _shingles(_words(r), min_words) & shot_grams]
    n = len(reasons)
    return {"answered": n, "parroted": len(hits), "rate": round(len(hits) / n, 6) if n else None,
            "min_words": min_words, "examples": sorted(set(hits))[:3]}


def literal_shortcut(score: dict[str, Any], programs_dir: Path) -> dict[str, Any]:
    """Per label: outcomes at roots whose own pseudo-C holds a sanitizer error message, and at the rest."""
    table: dict[str, dict[str, Counter]] = {lab: {"with_literal": Counter(), "without_literal": Counter()}
                                            for lab in ("bad", "good")}
    progs: dict[str, dict[str, Any]] = {}
    for r in score["roots"]:
        if r["case_id"] not in progs:
            prog = json.loads((Path(programs_dir) / f"{r['case_id']}.json").read_text(encoding="utf-8"))
            progs[r["case_id"]] = {f["addr"]: f for f in prog["functions"]}
        fn = progs[r["case_id"]].get(r["addr"]) or {}
        part = "with_literal" if SANITIZER_LITERAL.search(fn.get("pseudo_c") or "") else "without_literal"
        table[r["label"]][part][r["outcome"]] += 1
    return {lab: {part: {"n": sum(c.values()), "flagged": c["flagged"], "clear": c["clear"],
                         "abstain": c["abstain"]} for part, c in parts.items()}
            for lab, parts in table.items()}