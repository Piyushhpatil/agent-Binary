"""Phase 10 scorer (D-042): R4, A1, A2 and R5 at the same Juliet roots, from persisted files only.

Four rungs, one judge. R4 is the no-context floor (Phase 8 baseline rows), A1 the scripted policy,
A2 the agent policy, R5 the fixed walk. The evidence block is the only input that differs, so a
difference between cells is attributable to it.

Four rules fail the scorer closed, each guarding one way the comparison could be a lie:
  1. a zero-fetch root whose A-cell differs from its R4 cell -> the harness itself adds something;
  2. a root whose metered total exceeds its cap        -> the caps did not hold;
  3. any taintwalk.llm module loaded in this process   -> a model could have been called while scoring;
  4. a root missing from any rung                      -> an incomplete run (a ceilinged run is void).

Reads only. Byte-identical on unchanged input. Splices one section into RESULTS.md.

    python -m taintwalk.eval.agent_score --dev            # development slice, not reportable
    python -m taintwalk.eval.agent_score --results-md docs/RESULTS.md
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

from taintwalk.config import REPO_ROOT, load_config
from taintwalk.eval.ablation import preregistered_tests
from taintwalk.eval.metrics import score_rung

# NOTE: analyze_one is deliberately NOT imported. It pulls in taintwalk.llm, which would trip this
# module's own rule 3 (no provider module may be loaded while scoring) on the very first call.
# real_score.py builds the same path inline for the same reason. _stem must stay identical to
# analysis.analyze_one.stem, and test_agent_score.py asserts that against the real function.
SCORE_VERSION = 1
BEGIN, END = "<!-- phase10:begin -->", "<!-- phase10:end -->"

# The pre-registered family (D-042): 3 comparisons x 2 label sets = 6 tests, Holm at 0.05.
P10_COMPARISONS = (("A2vR5", "A2", "R5"), ("A2vA1", "A2", "A1"), ("A2vR4", "A2", "R4"))
RUNGS = ("R4", "A1", "A2", "R5")

# Counts a primary confusion dict must carry (D-008 cells, from metrics._cell). Validated once,
# with the real key list in the error, so a shape mismatch is one line to read instead of a
# traceback three calls deep.
COUNT_KEYS = ("TP", "FN", "FP", "TN")
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
        out[rung] = {
            "policy": policy, "roots": len(steps),
            "steps": _dist(steps), "metered_tokens": _dist(metered),
            "summaries_fetched": _dist(fetched), "code_reads": _dist(reads),
            "stops": dict(sorted(stops.items())),
            "invalid_actions": invalid, "repeated_actions": repeated, "zero_fetch_roots": zero,
        }
    return out


# --------------------------------------------------------------------------- cells

def _cells(scored: dict[str, Any], rung: str) -> dict[str, Any]:
    """The pooled primary confusion dict, validated once so a shape surprise names itself."""
    strata = scored.get("strata") or {}
    if "pooled" not in strata:
        raise AgentScoreError(f"{rung}: no pooled stratum; strata are {sorted(strata)}")
    c = strata["pooled"].get("primary")
    if not isinstance(c, dict):
        raise AgentScoreError(f"{rung}: pooled stratum has no primary confusion dict")
    missing = [k for k in COUNT_KEYS if k not in c]
    if missing:
        raise AgentScoreError(
            f"{rung}: primary confusion lacks {missing}; its actual keys are {sorted(c)}")
    if not any(k in c for k in ABSTAIN_KEYS):
        raise AgentScoreError(
            f"{rung}: primary confusion has no abstention count (tried {list(ABSTAIN_KEYS)}); "
            f"its actual keys are {sorted(c)}")
    return c


def _abstain(c: dict[str, Any]) -> int:
    return sum(int(c.get(k) or 0) for k in ABSTAIN_KEYS if k in c)


# --------------------------------------------------------------------------- render

def _f(x: Any) -> str:
    return "\u2014" if x is None else (f"{x:.3f}" if isinstance(x, (int, float)) else str(x))


def _d(d: dict[str, Any]) -> str:
    return f"{d['median']}/{d['p90']}/{d['max']}"


def render(doc: dict[str, Any]) -> str:
    L = [BEGIN, "", "## Phase 10: agentic evidence gathering (D-042)", "",
         f"Status: {doc['status']}", "",
         "One judge for every rung; only the evidence block differs. "
         "R4 no evidence, A1 scripted reads, A2 agent-chosen reads, R5 the fixed walk.", "",
         "| Rung | TP | FN | FP | TN | Abstain | Recall | Specificity | Precision | Coverage |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for r in RUNGS:
        c = doc["cells"][r]
        L.append(f"| {r} | {c.get('TP', 0)} | {c.get('FN', 0)} | {c.get('FP', 0)} | "
                 f"{c.get('TN', 0)} | {_abstain(c)} | "
                 + " | ".join(_f(c.get(k)) for k in RATE_KEYS) + " |")

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
        L.append(f"\n{r} stop reasons: "
                 + ", ".join(f"{k} {v}" for k, v in doc["process"][r]["stops"].items()))

    L += ["", f"Floor check: {doc['floor']['zero_fetch_roots']} zero-fetch roots, all equal to "
              f"their R4 cell. Caps held on every root.", "", END, ""]
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
          status: str) -> dict[str, Any]:
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
    return {"score_version": SCORE_VERSION, "rules": "D-042", "status": status,
            "roots": len(next(iter(keys.values()))),
            "cells": {r: _cells(scored[r], r) for r in RUNGS},
            "tests": tests, "process": process_table(agent_root, cases), "floor": floor,
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
    args = ap.parse_args(argv)

    agent_root = args.agent_root or Path("runs/p10-dev" if args.dev else "runs/p10-scored")
    programs = args.programs or Path(
        "runs/p10/dev.programs.txt" if args.dev else "runs/p10/scored.programs.txt")
    status = ("development slice, not reportable (D-028)" if args.dev
              else "scored set, local model only (D-034)")
    try:
        cases = load_cases(programs)
        doc = score(agent_root, args.walk_root, cases, status=status)
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
    print(f"AGENT EVAL OK: {doc['roots']} roots, rungs {' '.join(RUNGS)}, "
          f"{len(t['tests'])} tests, Holm {'applied' if t['holm_applied'] else 'NOT applied'} "
          f"-> {out / 'agent.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())