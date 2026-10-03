"""Phase 9 scorer: real-code pairs, every rung at the roots (D-036, D-038, D-040). Eval side.

Reads persisted files only and never calls a model. The command line fails if a taintwalk.llm module
was loaded in its process.

Inputs (defaults in parentheses)
  manifest   pairs and binaries (config real.manifest: corpus/real/manifest.json)
  programs   one program.json per binary, <case>.json (runs/p9-real/programs)
  R1-R3      eval/baselines.rule_rung_docs over whole programs, which leaves every root's row unchanged
             (D-038 item 3); the documents and flawfinder's input tree go to <out>/rules/
  R4         analyze-one rows at the roots, <r4>/summaries/<sha12>_<addr>.json (runs/p9-real/r4; D-038 item 2)
  R5         the roots walk, every run dir under <walk> (runs/p9-real/walk), via baselines.llm_rung_doc
  Phase 8    <p8>/R1.json .. R5.json, Phase 8's score_rung output (runs/p8-eval/scores), for the gap table

Judge (D-040): D-008's primary rule at the root, detection level only. A root is flagged when its row
says vulnerable, clear when it says not vulnerable, and abstains when there is no summary (context
overflow, output truncated at max_tokens, a schema failure). Cells come from eval/metrics._cell, the
function Phase 8 scored with, imported so the rule cannot drift: a pre-fix (bad) root flagged is TP,
clear FN, abstain FN_abstain; a post-fix (good) root flagged is FP, clear TN, abstain abstain (never a
TN). The typed ladder is not run (D-038 item 5).

Pair outcomes: the four pre-registered ones, pair-correct (pre flagged, post clear), both-vulnerable,
both-clear and reversed (pre clear, post flagged), plus D-040's "abstained" (either root abstained; never
pair-correct). Pairs whose two roots both had no callee block in the walk are also shown apart (D-038
item 4). At such a root R4 and R5 saw the same prompt bytes, so their rows must be identical; a
difference fails the run.

Also reported, as pre-registered: the gap table against Phase 8 (recall and specificity; precision and
F1 beside a base-rate note), the post-fix roots that gained a string literal (the D-018 shortcut on real
code), indirect call sites in each root's closure (failure mode 5), and why roots abstained, per LLM
rung (failure mode 3 and output truncation).

Outputs: <out>/real.json (sorted keys, no timestamps, so an unchanged input rewrites it byte for byte),
<out>/results-p9.md, and with --results-md a marked Phase 9 section spliced into that file. Phase 8's
`taintwalk eval --results-md` rewrites RESULTS.md whole, so run this again after any such re-render.

usage: python -m taintwalk.eval.real_score [--results-md docs/RESULTS.md]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from taintwalk.analysis.callgraph import build_graph, downward_closure
from taintwalk.analysis.findings import FindingsError
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.eval.baselines import DEFINITIONS, RungError, _row_from_file, llm_rung_doc, rule_rung_docs, write_doc
from taintwalk.eval.metrics import OUTCOMES, _cell, _rate, confusion
from taintwalk.eval.score import CONF_HEADER, _conf_cells, _r, _table, _x, discover_runs

REAL_SCORE_VERSION = 1
RUNGS = ("R1", "R2", "R3", "R4", "R5")
LLM_RUNGS = ("R4", "R5")
SIDES = (("pre", "bad"), ("post", "good"))
PAIR_OUTCOMES = ("pair_correct", "both_vulnerable", "both_clear", "reversed", "abstained")
LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"')
BEGIN, END = "<!-- phase9:begin -->", "<!-- phase9:end -->"
SHORT = {"flagged": "F", "clear": "C", "abstain": "A"}
DEFAULT_STATUS = ("REPORTABLE: Phase 9 held-out real-code result (pre-registered, D-036; scorer D-040). "
                  "Descriptive only; never pooled with Juliet.")


class RealScoreError(RuntimeError):
    """The inputs do not line up exactly; nothing is scored."""


# ---- inputs -----------------------------------------------------------------------------------

def load_roots(manifest: dict[str, Any], programs_dir: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Two roots per included pair (pre: bad, post: good), each re-checked against the manifest entry's
    own label, and the program.json of every binary they live in, re-checked against the stripped sha."""
    entries = {e["case_id"]: e for e in manifest["entries"]}
    if len(entries) != len(manifest["entries"]):
        raise RealScoreError("manifest has duplicate case ids")
    pairs = sorted((p for p in manifest["pairs"] if p["excluded_by"] is None), key=lambda p: p["pair_id"])
    if not pairs:
        raise RealScoreError("manifest has no included pairs")
    progs: dict[str, dict[str, Any]] = {}
    roots: list[dict[str, Any]] = []
    for p in pairs:
        for side, label in SIDES:
            case, addr = p[side], p[f"{side}_addr"]
            e = entries.get(case)
            if e is None:
                raise RealScoreError(f"{p['pair_id']} {side}: binary {case} is not in the manifest")
            hits = [f for f in e["functions"] if f["addr_hex"] == addr]
            if len(hits) != 1 or hits[0]["label"] != label or hits[0].get("pair") != p["pair_id"]:
                raise RealScoreError(f"{p['pair_id']} {side}: {case} does not label {addr} {label} for this pair")
            if case not in progs:
                path = Path(programs_dir) / f"{case}.json"
                if not path.exists():
                    raise RealScoreError(f"{path} is missing")
                prog = json.loads(path.read_text(encoding="utf-8"))
                if prog["binary"]["sha256"] != e["stripped_sha256"]:
                    raise RealScoreError(f"{path.name} is binary {prog['binary']['sha256'][:12]}, "
                                         f"the manifest says {e['stripped_sha256'][:12]}")
                progs[case] = prog
            roots.append({"pair_id": p["pair_id"], "cve": p["cve"], "project": p["project"], "function": p["root"],
                          "side": side, "label": label, "case_id": case, "addr": addr,
                          "binary_sha256": e["stripped_sha256"]})
    keys = [(r["binary_sha256"], r["addr"]) for r in roots]
    if len(set(keys)) != len(keys):
        raise RealScoreError("one function is the root of two pairs")
    return roots, progs


def _key(r: dict[str, Any]) -> tuple[str, str]:
    return r["binary_sha256"], r["addr"]


def _where(r: dict[str, Any]) -> str:
    return f"{r['pair_id']} {r['side']} {r['case_id']} {r['addr']}"


def r4_doc(r4_dir: Path, roots: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[tuple[str, str], str | None]]:
    """R4 from analyze-one's row file at each root (D-038 item 2) and, per root, why it abstained."""
    programs: dict[str, dict[str, Any]] = {}
    reasons: dict[tuple[str, str], str | None] = {}
    identity: dict[str, Any] | None = None
    for r in roots:
        sha, addr = _key(r)
        path = Path(r4_dir) / "summaries" / f"{sha[:12]}_{addr}.json"
        if not path.exists():
            raise RealScoreError(f"R4: {path} is missing (analyze-one was not run on {_where(r)})")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("binary_sha256") != sha or raw.get("address") != addr:
            raise RealScoreError(f"R4: {path.name} is the row of {str(raw.get('binary_sha256'))[:12]} "
                                 f"{raw.get('address')}, not of {_where(r)}")
        ident = {"provider": raw["provider"], "prompt_version": raw["prompt_version"]}
        if identity is None:
            identity = ident
        elif ident != identity:
            raise RealScoreError(f"R4: {path.name} was produced by {ident}, earlier rows by {identity}; never pooled")
        try:
            row = _row_from_file(path, addr)
        except RungError as e:
            raise RealScoreError(f"R4: {e}") from e
        if (row["outcome"] == "abstain") != (raw["status"] != "ok"):
            raise RealScoreError(f"R4: {path.name} says status {raw['status']!r} but its record disagrees")
        programs.setdefault(sha, {})[addr] = row
        reasons[(sha, addr)] = None if raw["status"] == "ok" else (raw.get("failure") or raw["status"])
    doc = {"rung": "R4", "kind": "llm", "score_scale": "probability", "definition": DEFINITIONS["R4"],
           "identity": {**(identity or {}), "arm": "analyze-one at the root (D-038 item 2)"}, "programs": programs}
    return doc, reasons


def r5_doc(walk_root: Path, roots: list[dict[str, Any]]
           ) -> tuple[dict[str, Any], dict[tuple[str, str], str | None], dict[tuple[str, str], int]]:
    """R5 from the roots walk (baselines.llm_rung_doc: provider and prompt version checked there), why each
    root abstained, and how many characters of callee block each root's walk prompt carried."""
    try:
        doc = llm_rung_doc(Path(walk_root), "R5")
    except (RungError, FindingsError) as e:
        raise RealScoreError(f"R5: {e}") from e
    walks: dict[str, dict[str, Any]] = {}
    for d in discover_runs(Path(walk_root)):
        w = json.loads((d / "walk.json").read_text(encoding="utf-8"))
        walks[w["binary_sha256"]] = w
    reasons: dict[tuple[str, str], str | None] = {}
    ctx: dict[tuple[str, str], int] = {}
    for r in roots:
        sha, addr = _key(r)
        w = walks.get(sha)
        if w is None or addr not in w["functions"] or addr not in doc["programs"].get(sha, {}):
            raise RealScoreError(f"R5: no walk row for {_where(r)} (its run dir is missing or the root was not walked)")
        fn = w["functions"][addr]
        reasons[(sha, addr)] = None if fn["status"] == "ok" else (fn["failure"] or fn["status"])
        ctx[(sha, addr)] = fn["context_chars"]
    return doc, reasons, ctx


def load_p8(p8_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for k in RUNGS:
        path = Path(p8_dir) / f"{k}.json"
        if not path.exists():
            raise RealScoreError(f"Phase 8 score {path} is missing")
        s = json.loads(path.read_text(encoding="utf-8"))
        if s.get("rung") != k:
            raise RealScoreError(f"{path} holds rung {s.get('rung')!r}, not {k}")
        out[k] = s
    return out


# ---- scoring ----------------------------------------------------------------------------------

def pair_outcome(pre: str, post: str) -> str:
    """One pair under the paired-evaluation convention, plus D-040's abstained."""
    if pre not in OUTCOMES or post not in OUTCOMES:
        raise RealScoreError(f"unknown outcome {pre!r}/{post!r}")
    if "abstain" in (pre, post):
        return "abstained"
    return {("flagged", "clear"): "pair_correct", ("flagged", "flagged"): "both_vulnerable",
            ("clear", "clear"): "both_clear", ("clear", "flagged"): "reversed"}[(pre, post)]


def _row(doc: dict[str, Any], r: dict[str, Any]) -> dict[str, Any]:
    row = doc["programs"].get(r["binary_sha256"], {}).get(r["addr"])
    if row is None:
        raise RealScoreError(f"{doc['rung']}: no row for {_where(r)}")
    if not isinstance(row, dict) or row.get("outcome") not in OUTCOMES:
        raise RealScoreError(f"{doc['rung']}: the row for {_where(r)} has no valid outcome")
    return row


def _fn(prog: dict[str, Any], addr: str) -> dict[str, Any]:
    hits = [f for f in prog["functions"] if f["addr"] == addr]
    if len(hits) != 1:
        raise RealScoreError(f"{prog['binary']['sha256'][:12]}: {len(hits)} functions at {addr}")
    return hits[0]


def literals(pseudo_c: str | None) -> set[str]:
    return set(LITERAL.findall(pseudo_c or ""))


def _closure_facts(prog: dict[str, Any], addr: str) -> dict[str, int]:
    """Size of the root's downward closure and its indirect call sites (failure mode 5)."""
    closure = downward_closure(build_graph(prog), (addr,))
    sites = sum(f["indirect_call_sites"] for f in prog["functions"] if f["addr"] in closure)
    return {"closure": len(closure), "indirect_call_sites": sites}


def _pair_counts(pairs: list[dict[str, Any]], rung: str) -> dict[str, Any]:
    c = Counter(p["outcomes"][rung] for p in pairs)
    n = len(pairs)
    return {"pairs": n, **{o: c[o] for o in PAIR_OUTCOMES},
            "pair_correct_rate": _rate(c["pair_correct"], n),
            "both_vulnerable_rate": _rate(c["both_vulnerable"], n)}


def _delta(a: float | None, b: float | None) -> float | None:
    return None if a is None or b is None else round(b - a, 6)


def score_real(roots: list[dict[str, Any]], docs: dict[str, dict[str, Any]], *,
               reasons: dict[str, dict[tuple[str, str], str | None]], context_chars: dict[tuple[str, str], int],
               progs: dict[str, dict[str, Any]], p8: dict[str, dict[str, Any]],
               manifest_sha256: str) -> dict[str, Any]:
    """Every rung at every root, the pairs, and the pre-registered side tables. Deterministic."""
    missing = [k for k in RUNGS if k not in docs]
    if missing:
        raise RealScoreError(f"rung documents missing: {missing}")
    a, b = docs["R4"]["identity"], docs["R5"]["identity"]
    if (a.get("provider"), a.get("prompt_version")) != (b.get("provider"), b.get("prompt_version")):
        raise RealScoreError(f"R4 and R5 come from different providers or prompt versions: "
                             f"{a.get('provider')} {a.get('prompt_version')} vs {b.get('provider')} {b.get('prompt_version')}")

    per_root: list[dict[str, Any]] = []
    rung_rows: dict[str, list[dict[str, Any]]] = {k: [] for k in RUNGS}
    for r in roots:
        key = _key(r)
        rows = {k: _row(docs[k], r) for k in RUNGS}
        if key not in context_chars:
            raise RealScoreError(f"no walk context size for {_where(r)}")
        if context_chars[key] == 0 and rows["R4"] != rows["R5"]:
            raise RealScoreError(f"{_where(r)}: R4 and R5 rows differ at a root whose walk prompt had no callee "
                                 "block; the same prompt bytes must give the same row (D-038 item 4)")
        rec = {**r, "outcomes": {k: rows[k]["outcome"] for k in RUNGS},
               "cells": {k: _cell(r["label"], rows[k]["outcome"]) for k in RUNGS},
               "abstain_reason": {k: reasons[k][key] for k in LLM_RUNGS},
               "context_chars": context_chars[key],
               **_closure_facts(progs[r["case_id"]], r["addr"])}
        for k in RUNGS:
            rung_rows[k].append({"label": r["label"], "outcome": rec["outcomes"][k], "cell": rec["cells"][k]})
        per_root.append(rec)

    sides: dict[str, dict[str, dict[str, Any]]] = {}
    for rec in per_root:
        sides.setdefault(rec["pair_id"], {})[rec["side"]] = rec
    pairs: list[dict[str, Any]] = []
    for pid in sorted(sides):
        pre, post = sides[pid]["pre"], sides[pid]["post"]
        gained = sorted(literals(_fn(progs[post["case_id"]], post["addr"]).get("pseudo_c"))
                        - literals(_fn(progs[pre["case_id"]], pre["addr"]).get("pseudo_c")))
        pairs.append({
            "pair_id": pid, "cve": pre["cve"], "project": pre["project"], "function": pre["function"],
            "no_callee": pre["context_chars"] == 0 and post["context_chars"] == 0,
            "pre": {k: pre["outcomes"][k] for k in RUNGS}, "post": {k: post["outcomes"][k] for k in RUNGS},
            "outcomes": {k: pair_outcome(pre["outcomes"][k], post["outcomes"][k]) for k in RUNGS},
            "literals_gained": gained,
            "closure": {"pre": pre["closure"], "post": post["closure"]},
            "indirect_call_sites": {"pre": pre["indirect_call_sites"], "post": post["indirect_call_sites"]},
        })
    groups = {"all": pairs, "with_callees": [p for p in pairs if not p["no_callee"]],
              "no_callee": [p for p in pairs if p["no_callee"]]}

    rungs = {k: {"kind": docs[k]["kind"], "definition": docs[k]["definition"], "identity": docs[k]["identity"],
                 "primary": confusion(rung_rows[k])} for k in RUNGS}
    gap: dict[str, Any] = {}
    for k in RUNGS:
        a, b = p8[k]["strata"]["pooled"]["primary"], rungs[k]["primary"]
        gap[k] = {**{m: {"phase8": a[m], "phase9": b[m], "delta": _delta(a[m]["value"], b[m]["value"])}
                     for m in ("recall", "specificity")},
                  "precision": {"phase8": a["precision"], "phase9": b["precision"]},
                  "f1": {"phase8": a["f1"], "phase9": b["f1"]}}
    p8c = p8["R1"]["strata"]["pooled"]["primary"]
    gainers = [p for p in pairs if p["literals_gained"]]
    return {
        "real_score_version": REAL_SCORE_VERSION,
        "rules": "D-008 primary cells at the root, detection level; pair outcomes (D-036, D-040)",
        "manifest_sha256": manifest_sha256,
        "corpus": {"pairs": len(pairs), "roots": len(per_root),
                   "projects": dict(sorted(Counter(p["project"] for p in pairs).items())),
                   "no_callee_pairs": len(groups["no_callee"])},
        "base_rate": {"phase8": _rate(p8c["positives"], p8c["roots"]),
                      "phase9": _rate(sum(r["label"] == "bad" for r in per_root), len(per_root))},
        "rungs": rungs,
        "pair_outcomes": {g: {k: _pair_counts(ps, k) for k in RUNGS} for g, ps in groups.items()},
        "gap": gap,
        "abstentions": {k: dict(sorted(Counter(v for v in reasons[k].values() if v is not None).items()))
                        for k in LLM_RUNGS},
        "literal_gain": {"post_roots_gaining": len(gainers), "pairs": len(pairs),
                         "post_outcomes": {k: {o: sum(p["post"][k] == o for p in gainers) for o in OUTCOMES}
                                           for k in RUNGS}},
        "indirect_call_sites": {"roots_with_any": sum(r["indirect_call_sites"] > 0 for r in per_root),
                                "total_over_root_closures": sum(r["indirect_call_sites"] for r in per_root)},
        "pairs": pairs,
        "roots": per_root,
    }


def dumps(score: dict[str, Any]) -> str:
    return json.dumps(score, indent=1, sort_keys=True) + "\n"


# ---- report -----------------------------------------------------------------------------------

def _d(v: float | None) -> str:
    return "-" if v is None else f"{v:+.3f}"


def render(score: dict[str, Any], *, status: str, md: bool) -> list[str]:
    c = score["corpus"]
    br = score["base_rate"]
    head = "## " if md else ""
    sub = "### " if md else "== "
    out = [f"{head}Phase 9: real-code generalization (held out)", "", status, "",
           f"{c['pairs']} pairs ({', '.join(f'{k} {v}' for k, v in c['projects'].items())}), {c['roots']} roots; "
           f"unit: the pair; root: the function the fix changed (D-008 as amended). Judge: D-008 primary cells at the "
           f"root, detection level (D-040). 95% Wilson intervals; no p-values (pre-registered)."]

    def section(title: str, intro: str | None, header: list[str], rows: list[list[Any]]) -> None:
        out.extend(["", f"{sub}{title}"])
        if intro:
            out.extend(["", intro])
        out.extend(["", *_table(header, rows, md=md)])

    section("Every rung at the roots", None, ["rung", *CONF_HEADER],
            [[k, *_conf_cells(score["rungs"][k]["primary"])] for k in RUNGS])
    for g, title in (("all", "Pair outcomes"), ("with_callees", "Pair outcomes: roots with a callee block"),
                     ("no_callee", "Pair outcomes: no callee block at either root (R4 and R5 saw the same prompts)")):
        po = score["pair_outcomes"][g]
        section(title, None, ["rung", "pairs", "pair-correct", "both vulnerable", "both clear", "reversed",
                              "abstained", "pair-correct rate", "both-vulnerable rate"],
                [[k, po[k]["pairs"], *(po[k][o] for o in PAIR_OUTCOMES), _r(po[k]["pair_correct_rate"]),
                  _r(po[k]["both_vulnerable_rate"])] for k in RUNGS])
    gap = score["gap"]
    section("Gap against Phase 8 (Juliet, pooled, primary)",
            "Recall and specificity do not depend on the positive rate. Delta = Phase 9 minus Phase 8.",
            ["rung", "recall P8", "recall P9", "delta", "specificity P8", "specificity P9", "delta"],
            [[k, _r(gap[k]["recall"]["phase8"]), _r(gap[k]["recall"]["phase9"]), _d(gap[k]["recall"]["delta"]),
              _r(gap[k]["specificity"]["phase8"]), _r(gap[k]["specificity"]["phase9"]),
              _d(gap[k]["specificity"]["delta"])] for k in RUNGS])
    section("Precision and F1, with the base rate",
            f"Base rate: Phase 8 roots are {_r(br['phase8'])} positive; this corpus is {_r(br['phase9'])} by "
            "construction. Neither resembles real code, so precision and F1 do not transfer between them.",
            ["rung", "precision P8", "precision P9", "F1 P8", "F1 P9"],
            [[k, _r(gap[k]["precision"]["phase8"]), _r(gap[k]["precision"]["phase9"]), _x(gap[k]["f1"]["phase8"]),
              _x(gap[k]["f1"]["phase9"])] for k in RUNGS])
    ab = score["abstentions"]
    section("Why roots abstained", None, ["rung", "reason", "roots"],
            [[k, why, n] for k in LLM_RUNGS for why, n in ab[k].items()] or [["-", "none", 0]])
    lg = score["literal_gain"]
    section("Post-fix literal gain (the D-018 shortcut on real code)",
            f"{lg['post_roots_gaining']} of {lg['pairs']} post-fix roots gained a string literal the pre-fix root "
            "lacked. Outcomes at those post-fix roots:",
            ["rung", "flagged", "clear", "abstain"],
            [[k, *(lg["post_outcomes"][k][o] for o in OUTCOMES)] for k in RUNGS])
    ic = score["indirect_call_sites"]
    section("Root closures and indirect calls (failure mode 5)",
            f"{ic['roots_with_any']} of {c['roots']} roots reach an indirect call site; "
            f"{ic['total_over_root_closures']} sites summed over the root closures.",
            ["pair", "function", "closure pre", "closure post", "indirect pre", "indirect post"],
            [[p["pair_id"], p["function"], p["closure"]["pre"], p["closure"]["post"],
              p["indirect_call_sites"]["pre"], p["indirect_call_sites"]["post"]] for p in score["pairs"]])
    section("Every pair",
            "Pre/post outcome per rung: F flagged, C clear, A abstained.",
            ["pair", "CVE", "project", "function", "no callee", *RUNGS],
            [[p["pair_id"], p["cve"], p["project"], p["function"], "yes" if p["no_callee"] else "",
              *(f"{SHORT[p['pre'][k]]}/{SHORT[p['post'][k]]}" for k in RUNGS)] for p in score["pairs"]])
    return out


def splice(path: Path, section: str) -> None:
    """Put `section` between the Phase 9 markers in `path`, replacing an earlier one in place, or append
    it. Running it twice with the same section leaves the file byte-identical."""
    path = Path(path)
    if not path.exists():
        raise RealScoreError(f"{path} does not exist (Phase 8's eval writes it)")
    text = path.read_text(encoding="utf-8")
    block = f"{BEGIN}\n{section.rstrip()}\n{END}\n"
    nb, ne = text.count(BEGIN), text.count(END)
    if nb == ne == 0:
        new = text.rstrip("\n") + "\n\n" + block
    elif nb == ne == 1 and text.index(BEGIN) < text.index(END):
        i, j = text.index(BEGIN), text.index(END) + len(END)
        rest = text[j:]
        new = text[:i] + block + (rest[1:] if rest.startswith("\n") else rest)
    else:
        raise RealScoreError(f"{path}: the Phase 9 markers are malformed ({nb} begin, {ne} end)")
    path.write_text(new, encoding="utf-8")


# ---- command line -----------------------------------------------------------------------------

def _abs(p: str | None) -> Path | None:
    if p is None:
        return None
    q = Path(p)
    return q if q.is_absolute() else REPO_ROOT / q


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m taintwalk.eval.real_score",
                                 description="Phase 9: score R1-R5 at the real-code roots (D-036, D-038, D-040).")
    ap.add_argument("--manifest", help="real-code manifest (default: config real.manifest)")
    ap.add_argument("--programs", default="runs/p9-real/programs")
    ap.add_argument("--r4", default="runs/p9-real/r4", help="analyze-one run dir of the roots")
    ap.add_argument("--walk", default="runs/p9-real/walk", help="root of the roots-walk run dirs")
    ap.add_argument("--p8-scores", default="runs/p8-eval/scores", help="Phase 8 R1.json..R5.json")
    ap.add_argument("--out", default="runs/p9-real/eval")
    ap.add_argument("--results-md", help="splice the Phase 9 section into this file, e.g. docs/RESULTS.md")
    ap.add_argument("--status", default=DEFAULT_STATUS)
    args = ap.parse_args(argv)
    manifest_path = _abs(args.manifest) or REPO_ROOT / load_config()["real"]["manifest"]
    out = _abs(args.out)
    try:
        raw = manifest_path.read_bytes()
        roots, progs = load_roots(json.loads(raw), _abs(args.programs))
        rules = rule_rung_docs(_abs(args.programs), out / "rules")
        r4, r4_why = r4_doc(_abs(args.r4), roots)
        r5, r5_why, ctx = r5_doc(_abs(args.walk), roots)
        p8 = load_p8(_abs(args.p8_scores))
        score = score_real(roots, {**rules, "R4": r4, "R5": r5}, reasons={"R4": r4_why, "R5": r5_why},
                           context_chars=ctx, progs=progs, p8=p8, manifest_sha256=hashlib.sha256(raw).hexdigest())
    except (RealScoreError, RungError, FindingsError, ValueError, OSError) as e:
        print(f"REAL EVAL FAIL: {e}")
        return 1
    for k, d in rules.items():
        write_doc(d, out / "rules" / f"{k}.json")
    out.mkdir(parents=True, exist_ok=True)
    (out / "real.json").write_text(dumps(score), encoding="utf-8")
    md = "\n".join(render(score, status=args.status, md=True)) + "\n"
    (out / "results-p9.md").write_text(md, encoding="utf-8")
    print("\n".join(render(score, status=args.status, md=False)))
    print(f"\nscore              : {out / 'real.json'}")
    if args.results_md:
        try:
            splice(_abs(args.results_md), md)
        except RealScoreError as e:
            print(f"REAL EVAL FAIL: {e}")
            return 1
        print(f"results            : Phase 9 section spliced into {_abs(args.results_md)}")
    loaded = sorted(m for m in sys.modules if m == "taintwalk.llm" or m.startswith("taintwalk.llm."))
    print(f"llm calls          : 0 in this process; provider modules loaded: {', '.join(loaded) or 'none'}")
    if loaded:
        print("REAL EVAL FAIL: a provider module was loaded")
        return 1
    c = score["corpus"]
    print(f"REAL EVAL OK: {c['pairs']} pairs, {c['roots']} roots, rungs {' '.join(RUNGS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())