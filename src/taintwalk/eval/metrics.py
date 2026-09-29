"""Phase 7 scoring (eval side): the D-008 rules over label-free findings.

Unit of scoring (D-008): the path root. Every binary has one bad path, rooted at its bad/entry
function, and one or more good paths, each rooted at a good/path function. Exactly one function per
path is scored: the root, where both the source (in the fixed-sink stratum, the unsafe setup) and
the unsafe operation are in view.

Outcomes: a root's walk summary says vulnerable ("flagged"), not vulnerable ("clear"), or there is
no summary ("abstain": a terminal model failure, a context overflow, or a root the walk never
reached). Cells:
  bad root:  flagged -> TP   clear -> FN   abstain -> FN_abstain  (a miss: counts against recall)
  good root: flagged -> FP   clear -> TN   abstain -> abstain     (never a TN)
So a missing summary can never raise recall, specificity or coverage. Precision is over emitted
findings only, which is why coverage is always reported next to it.

Secondary rule ("any member"; always beside the primary, never promoted): a path's members are its
root plus the same-label scored functions reachable from it in the in-scope call graph. The path is
flagged if any member is flagged, else abstains if any member abstains, else is clear.

Typed ladder at the root: detection (vulnerable), mechanism (the mechanism D-021 maps the case's
class to), exact (the D-021 derivation equals the class). Precision at every level is typed TPs over
all root findings.

Joins (D-008, D-017): run -> manifest entry by the stripped binary's sha256; label file and
program.json by that entry's case id, each re-checked against the sha; functions by address (I4).
Any mismatch raises ScoreError. Runs from different providers or prompt versions are never pooled.
Accuracy is never computed.

Phase 8 (D-030): every rung is scored by this same code. A rung row per walked function is
{"outcome": "flagged" | "clear" | "abstain", "score": number | None, "verdict": {...} | None}.
row_from_finding() turns a walk finding into one; eval/baselines.py builds the other rungs' rows.
score_rows() is the per-binary core shared by score_runs() (walk run dirs, the Phase 7 path, whose
output is unchanged) and score_rung() (one rung document). The typed ladder needs a factored verdict,
so it exists for LLM rungs only. A rung's score feeds AUROC; the reliability table and ECE exist only
on the probability scale.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from taintwalk.analysis.callgraph import addr_key, build_graph
from taintwalk.analysis.findings import VERDICT_FIELDS, build_findings
from taintwalk.config import REPO_ROOT
from taintwalk.eval.cwe_map import AMBIGUOUS, cwe_of_verdict, expected_mechanism
from taintwalk.eval.join import entries_by_stripped_sha

SCORE_VERSION = 1
Z95 = 1.959963984540054
ROOT_ROLES = frozenset({("bad", "entry"), ("good", "path")})
STRATA = ("external", "fixed_sink")
CELLS = ("TP", "FN", "FN_abstain", "FP", "TN", "abstain")
LEVELS = ("detection", "mechanism", "exact")
N_BINS = 10
OUTCOMES = ("flagged", "clear", "abstain")
RUNG_KINDS = ("rule", "llm")
SCORE_SCALES = ("ordinal", "probability", None)
RUNG_DOC_KEYS = ("rung", "kind", "score_scale", "definition", "identity", "programs")


class ScoreError(RuntimeError):
    """The inputs do not join exactly; nothing is scored (D-008)."""


# ---- statistics -----------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = Z95) -> list[float] | None:
    """95% Wilson score interval for k successes out of n (None when n == 0). Unlike the normal
    approximation it stays inside [0, 1] and is not degenerate at k = 0 or k = n."""
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)]


def _rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "value": None if n == 0 else round(k / n, 6), "ci95": wilson(k, n)}


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None:
        return None
    return 0.0 if p + r == 0 else round(2 * p * r / (p + r), 6)


# ---- one root -------------------------------------------------------------------------------

def _outcome(f: dict[str, Any] | None) -> str:
    if f is None or f["status"] != "ok":
        return "abstain"
    return "flagged" if f["vulnerable"] else "clear"


def _cell(label: str, outcome: str) -> str:
    if label == "bad":
        return {"flagged": "TP", "clear": "FN", "abstain": "FN_abstain"}[outcome]
    return {"flagged": "FP", "clear": "TN", "abstain": "abstain"}[outcome]


def row_from_finding(f: dict[str, Any] | None) -> dict[str, Any] | None:
    """A walk finding as a rung row (D-030). None stays None: the function was not walked."""
    if f is None:
        return None
    if f["status"] != "ok":
        return {"outcome": "abstain", "score": None, "verdict": None}
    conf = f["confidence"]
    return {"outcome": "flagged" if f["vulnerable"] else "clear",
            "score": round(conf if f["vulnerable"] else 1 - conf, 6),
            "verdict": {k: f[k] for k in VERDICT_FIELDS}}


def _row_outcome(row: dict[str, Any] | None) -> str:
    return "abstain" if row is None else row["outcome"]


def judge_row(label: str, row: dict[str, Any] | None, cwe: str) -> dict[str, Any]:
    """One path root under D-008 for any rung: outcome, cell, typed levels (only when the rung has a
    factored verdict) and its ranking score."""
    outcome = _row_outcome(row)
    if outcome not in OUTCOMES:
        raise ScoreError(f"unknown outcome {outcome!r}")
    answered = outcome != "abstain"
    v = row["verdict"] if answered else None
    flagged_bad = outcome == "flagged" and label == "bad"
    derived = cwe_of_verdict(v) if outcome == "flagged" and v is not None else None
    return {
        "label": label, "outcome": outcome, "cell": _cell(label, outcome),
        "not_walked": row is None,
        "mechanism": v["mechanism"] if v is not None else None,
        "derived_cwe": derived,
        "mechanism_ok": bool(flagged_bad and v is not None and v["mechanism"] == expected_mechanism(cwe)),
        "exact_ok": bool(flagged_bad and derived == cwe),
        "confidence": v["confidence"] if v is not None else None,
        "score": row["score"] if answered else None,
    }


def judge_root(label: str, finding: dict[str, Any] | None, cwe: str) -> dict[str, Any]:
    """One path root of a walk run (the Phase 7 signature): judge_row over the finding's row."""
    return judge_row(label, row_from_finding(finding), cwe)


# ---- paths ----------------------------------------------------------------------------------

def graph_succ(prog: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """In-scope successor map with an entry for every in-scope function (analysis/callgraph.py)."""
    g = build_graph(prog)
    return {n: tuple(g.succ.get(n, ())) for n in g.nodes}


def path_sets(succ: Mapping[str, Iterable[str]],
              functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Path root -> {label, members}: the root plus the same-label scored functions reachable
    from it."""
    lab = {f["addr"]: f for f in functions}
    out: dict[str, dict[str, Any]] = {}
    for r in sorted((a for a, f in lab.items() if (f["label"], f["role"]) in ROOT_ROLES), key=addr_key):
        if r not in succ:
            raise ScoreError(f"path root {r} is not an in-scope function")
        label = lab[r]["label"]
        seen, stack = {r}, [r]
        while stack:
            for c in succ.get(stack.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    stack.append(c)
        members = sorted((a for a in seen if a in lab and lab[a]["label"] == label and lab[a]["scored"]),
                         key=addr_key)
        out[r] = {"label": label, "members": members}
    return out


def audit_paths(succ: Mapping[str, Iterable[str]], functions: list[dict[str, Any]]) -> dict[str, Any]:
    """Structural facts D-008 relies on, from labels and the call graph only (no model output)."""
    ps = path_sets(succ, functions)
    lab = {f["addr"]: f for f in functions}
    owners: dict[str, list[str]] = defaultdict(list)
    for r, p in ps.items():
        for m in p["members"]:
            owners[m].append(r)
    below = [a for a, f in lab.items() if f["scored"] and f["role"] not in ("entry", "path")]
    return {
        "bad_roots": sum(p["label"] == "bad" for p in ps.values()),
        "good_roots": sum(p["label"] == "good" for p in ps.values()),
        "orphans": sorted((a for a in below if not owners[a]), key=addr_key),
        "shared": sorted((a for a in below if len(owners[a]) > 1), key=addr_key),
        "nested": sorted((r for r in ps if len(owners[r]) > 1), key=addr_key),
        "dispatchers_in_paths": sorted((a for a, f in lab.items()
                                        if (f["label"], f["role"]) == ("good", "entry") and owners[a]),
                                       key=addr_key),
    }


# ---- one binary -----------------------------------------------------------------------------

def score_rows(rows_by: Mapping[str, dict[str, Any] | None], binary_sha256: str, labels: dict[str, Any],
               succ: Mapping[str, Iterable[str]],
               entry: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Root rows and diagnostic rows (every other walked function) for one binary and one rung."""
    case = entry["case_id"]
    lab = {f["addr"]: f for f in labels["functions"]}
    unlabeled = sorted(set(rows_by) - set(lab), key=addr_key)
    if unlabeled:
        raise ScoreError(f"{case}: walked functions with no label entry {unlabeled[:5]}")
    ps = path_sets(succ, labels["functions"])
    n_bad = sum(p["label"] == "bad" for p in ps.values())
    if n_bad != 1 or len(ps) < 2:
        raise ScoreError(f"{case}: {n_bad} bad path roots and {len(ps) - n_bad} good ones; "
                         "expected exactly 1 bad and at least 1 good")
    common = {"case_id": case, "binary_sha256": binary_sha256, "cwe": entry["cwe"],
              "flow_variant": entry["flow_variant"], "stratum": entry["stratum"]}
    roots = []
    for r, p in ps.items():
        judged = judge_row(p["label"], rows_by.get(r), entry["cwe"])
        outs = [_row_outcome(rows_by.get(m)) for m in p["members"]]
        sec = "flagged" if "flagged" in outs else ("abstain" if "abstain" in outs else "clear")
        roots.append({**common, "addr": r, "role": lab[r]["role"], **judged, "members": p["members"],
                      "secondary_outcome": sec, "secondary_cell": _cell(p["label"], sec)})
    diags = [{**common, "addr": a, "label": lab[a]["label"], "role": lab[a]["role"], "outcome": _row_outcome(row)}
             for a, row in sorted(rows_by.items(), key=lambda kv: addr_key(kv[0])) if a not in ps]
    return roots, diags


def score_binary(findings: dict[str, Any], labels: dict[str, Any], succ: Mapping[str, Iterable[str]],
                 entry: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """One walk run's binary (the Phase 7 signature): score_rows over its findings."""
    rows_by = {f["address"]: row_from_finding(f) for f in findings["findings"]}
    return score_rows(rows_by, findings["binary_sha256"], labels, succ, entry)


# ---- aggregates -----------------------------------------------------------------------------

def confusion(rows: list[dict[str, Any]], key: str = "cell") -> dict[str, Any]:
    c = Counter(r[key] for r in rows)
    pos = sum(r["label"] == "bad" for r in rows)
    tp, fp, tn = c["TP"], c["FP"], c["TN"]
    answered = len(rows) - c["FN_abstain"] - c["abstain"]
    prec, rec = _rate(tp, tp + fp), _rate(tp, pos)
    return {"roots": len(rows), "positives": pos, "negatives": len(rows) - pos,
            "cells": {k: c[k] for k in CELLS},
            "precision": prec, "recall": rec, "specificity": _rate(tn, len(rows) - pos),
            "coverage": _rate(answered, len(rows)), "f1": _f1(prec["value"], rec["value"])}


def typed(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positives = sum(r["label"] == "bad" for r in rows)
    flagged = [r for r in rows if r["outcome"] == "flagged"]
    bad_flagged = [r for r in flagged if r["label"] == "bad"]
    out: dict[str, Any] = {"root_findings": len(flagged)}
    for level in LEVELS:
        tp = len(bad_flagged) if level == "detection" else sum(r[f"{level}_ok"] for r in bad_flagged)
        prec, rec = _rate(tp, len(flagged)), _rate(tp, positives)
        out[level] = {"tp": tp, "precision": prec, "recall": rec, "f1": _f1(prec["value"], rec["value"])}
    wrong: Counter = Counter()
    for r in bad_flagged:
        if r["exact_ok"]:
            continue
        if r["derived_cwe"] == AMBIGUOUS:
            wrong["ambiguous"] += 1
        elif not r["mechanism_ok"]:
            wrong["wrong_mechanism"] += 1
        else:
            wrong["right_mechanism_wrong_field"] += 1
    out["right_bug_wrong_cwe"] = {**{k: wrong[k] for k in ("ambiguous", "right_mechanism_wrong_field",
                                                           "wrong_mechanism")},
                                  "total": sum(wrong.values())}
    return out


def confidence_metrics(rows: list[dict[str, Any]], *, calibration: bool = True) -> dict[str, Any]:
    """AUROC of the ranking score (ties count 0.5) over answered roots that have one, and, on the
    probability scale only, a 10-bin reliability table with ECE. For LLM rungs s = confidence if
    vulnerable else 1 - confidence (S2: ordinal until here)."""
    pts = [(r["score"], r["label"] == "bad") for r in rows
           if r["outcome"] != "abstain" and r["score"] is not None]
    pos = [s for s, bad in pts if bad]
    neg = [s for s, bad in pts if not bad]
    auroc = None
    if pos and neg:
        wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in pos for b in neg)
        auroc = round(wins / (len(pos) * len(neg)), 6)
    if not calibration:
        return {"answered": len(pts), "auroc": auroc, "ece": None, "bins": []}
    bins, ece = [], 0.0
    for i in range(N_BINS):
        members = [(s, bad) for s, bad in pts if min(int(s * N_BINS), N_BINS - 1) == i]
        if not members:
            continue
        mean_s = sum(s for s, _ in members) / len(members)
        frac = sum(bad for _, bad in members) / len(members)
        ece += len(members) / len(pts) * abs(frac - mean_s)
        bins.append({"bin": [round(i / N_BINS, 6), round((i + 1) / N_BINS, 6)], "n": len(members),
                     "mean_score": round(mean_s, 6), "fraction_bad": round(frac, 6)})
    return {"answered": len(pts), "auroc": auroc, "ece": round(ece, 6) if pts else None, "bins": bins}


def diagnostics_summary(diags: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    c: dict[str, Counter] = defaultdict(Counter)
    for d in diags:
        k = f"{d['label']}/{d['role'] or '-'}"
        c[k]["n"] += 1
        c[k][d["outcome"]] += 1
    return {k: {"n": v["n"], "flagged": v["flagged"], "clear": v["clear"], "abstain": v["abstain"]}
            for k, v in sorted(c.items())}


# ---- many runs ------------------------------------------------------------------------------

def _rel(p: Path) -> str:
    p, root = Path(p).resolve(), Path(REPO_ROOT).resolve()
    return str(p.relative_to(root)) if p.is_relative_to(root) else str(p)


def _load(path: Path, what: str) -> dict[str, Any]:
    if not path.exists():
        raise ScoreError(f"{what} {path} is missing")
    return json.loads(path.read_text(encoding="utf-8"))


def _cwe_num(cwe: str) -> int:
    return int(cwe.split("-")[-1])


def _groups(roots: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {s: [x for x in roots if x["stratum"] == s] for s in STRATA}
    groups["pooled"] = roots
    return groups


def _breakdowns(groups: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "by_class": {k: {c: confusion([x for x in v if x["cwe"] == c])
                         for c in sorted({x["cwe"] for x in v}, key=_cwe_num)}
                     for k, v in groups.items()},
        "by_flow": {k: {f: confusion([x for x in v if x["flow_variant"] == f])
                        for f in sorted({x["flow_variant"] for x in v})}
                    for k, v in groups.items()},
    }


def score_runs(run_dirs: Iterable[Path], *, manifest: dict[str, Any], labels_dir: Path,
               programs_dir: Path) -> dict[str, Any]:
    """Score walk run dirs under D-008. Deterministic: no timestamps, sorted rows."""
    by_sha = entries_by_stripped_sha(manifest)
    roots: list[dict[str, Any]] = []
    diags: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    identity: dict[str, Any] | None = None
    for d in sorted({Path(x) for x in run_dirs}, key=_rel):
        fnd = build_findings(d)
        sha = fnd["binary_sha256"]
        ident = {k: fnd[k] for k in ("provider", "prompt_version", "callee_context_version")}
        if identity is None:
            identity = ident
        elif ident != identity:
            raise ScoreError(f"{d.name}: produced by {ident}, earlier runs by {identity}; "
                             "runs from different providers or prompt versions are never pooled")
        entry = by_sha.get(sha)
        if entry is None:
            raise ScoreError(f"{d.name}: binary {sha[:12]} is not in the manifest")
        if entry["stratum"] not in STRATA:
            raise ScoreError(f"{entry['case_id']}: unknown stratum {entry['stratum']!r}")
        case = entry["case_id"]
        if any(i["case_id"] == case for i in inputs):
            raise ScoreError(f"{d.name}: {case} is already scored from another run dir")
        labels = _load(Path(labels_dir) / f"{case}.json", "label file")
        if labels["program_sha256"] != sha:
            raise ScoreError(f"{case}: label file is for binary {labels['program_sha256'][:12]}, "
                             f"not {sha[:12]}")
        prog = _load(Path(programs_dir) / f"{case}.json", "program")
        if prog["binary"]["sha256"] != sha:
            raise ScoreError(f"{case}: program.json is for binary {prog['binary']['sha256'][:12]}, "
                             f"not {sha[:12]}")
        r, dg = score_binary(fnd, labels, graph_succ(prog), entry)
        roots += r
        diags += dg
        inputs.append({"run_dir": _rel(d), "case_id": case, "binary_sha256": sha,
                       "walked": fnd["walked"], "no_summary": fnd["no_summary"]})
    if identity is None:
        raise ScoreError("no walk run dirs to score")
    roots.sort(key=lambda x: (x["case_id"], addr_key(x["addr"])))
    inputs.sort(key=lambda x: x["case_id"])
    groups = _groups(roots)
    return {
        "score_version": SCORE_VERSION, "rules": "D-008", **identity,
        "inputs": inputs,
        "roots_not_walked": sum(x["not_walked"] for x in roots),
        "strata": {k: {"primary": confusion(v, "cell"), "secondary": confusion(v, "secondary_cell"),
                       "typed": typed(v), "confidence": confidence_metrics(v)}
                   for k, v in groups.items()},
        **_breakdowns(groups),
        "diagnostics": diagnostics_summary(diags),
        "roots": roots,
    }


def _joined(sha: str, by_sha: dict[str, dict[str, Any]], labels_dir: Path, programs_dir: Path,
            what: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Manifest entry, label file and program.json of one binary, each re-checked against the sha."""
    entry = by_sha.get(sha)
    if entry is None:
        raise ScoreError(f"{what}: binary {sha[:12]} is not in the manifest")
    if entry["stratum"] not in STRATA:
        raise ScoreError(f"{entry['case_id']}: unknown stratum {entry['stratum']!r}")
    case = entry["case_id"]
    labels = _load(Path(labels_dir) / f"{case}.json", "label file")
    if labels["program_sha256"] != sha:
        raise ScoreError(f"{case}: label file is for binary {labels['program_sha256'][:12]}, not {sha[:12]}")
    prog = _load(Path(programs_dir) / f"{case}.json", "program")
    if prog["binary"]["sha256"] != sha:
        raise ScoreError(f"{case}: program.json is for binary {prog['binary']['sha256'][:12]}, not {sha[:12]}")
    return entry, labels, prog


def score_rung(doc: dict[str, Any], *, manifest: dict[str, Any], labels_dir: Path,
               programs_dir: Path) -> dict[str, Any]:
    """Score one rung document (D-030) under exactly the D-008 code score_runs uses. Deterministic.
    Typed ladder for LLM rungs only; AUROC when the rung has a score; reliability bins and ECE only
    on the probability scale."""
    missing = [k for k in RUNG_DOC_KEYS if k not in doc]
    if missing:
        raise ScoreError(f"rung document lacks {missing}")
    rung = doc["rung"]
    if doc["kind"] not in RUNG_KINDS or doc["score_scale"] not in SCORE_SCALES:
        raise ScoreError(f"{rung}: kind {doc['kind']!r} or score_scale {doc['score_scale']!r} not recognised")
    by_sha = entries_by_stripped_sha(manifest)
    roots: list[dict[str, Any]] = []
    diags: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    for sha in sorted(doc["programs"]):
        rows = doc["programs"][sha]
        entry, labels, prog = _joined(sha, by_sha, labels_dir, programs_dir, rung)
        bad = sorted((a for a, row in rows.items()
                      if not isinstance(row, dict) or row.get("outcome") not in OUTCOMES), key=addr_key)
        if bad:
            raise ScoreError(f"{rung} {entry['case_id']}: rows without a valid outcome {bad[:3]}")
        r, dg = score_rows(rows, sha, labels, graph_succ(prog), entry)
        roots += r
        diags += dg
        inputs.append({"case_id": entry["case_id"], "binary_sha256": sha, "rows": len(rows),
                       "abstain": sum(row["outcome"] == "abstain" for row in rows.values())})
    if not inputs:
        raise ScoreError(f"{rung}: the rung document holds no programs")
    roots.sort(key=lambda x: (x["case_id"], addr_key(x["addr"])))
    inputs.sort(key=lambda x: x["case_id"])
    groups = _groups(roots)
    llm = doc["kind"] == "llm"
    return {
        "score_version": SCORE_VERSION, "rules": "D-008", "rung": rung, "kind": doc["kind"],
        "score_scale": doc["score_scale"], "definition": doc["definition"], "identity": doc["identity"],
        "inputs": inputs,
        "roots_not_walked": sum(x["not_walked"] for x in roots),
        "strata": {k: {"primary": confusion(v, "cell"), "secondary": confusion(v, "secondary_cell"),
                       "typed": typed(v) if llm else None,
                       "confidence": (confidence_metrics(v, calibration=doc["score_scale"] == "probability")
                                      if doc["score_scale"] is not None else None)}
                   for k, v in groups.items()},
        **_breakdowns(groups),
        "diagnostics": diagnostics_summary(diags),
        "roots": roots,
    }


def dumps_score(score: dict[str, Any]) -> str:
    """Canonical score.json text: sorted keys, fixed indent, trailing newline."""
    return json.dumps(score, indent=1, sort_keys=True) + "\n"