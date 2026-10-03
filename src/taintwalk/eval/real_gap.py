"""Phase 9 gap-analysis tooling (pre-registration "Gap analysis codebook"; D-035, D-040). Eval side.

Two commands, both CPU only and model-free. They run after real_score has written real.json.

  worksheet  One section per pair. A root is an item when its R5 cell is FN or FP (hand-coded from the
             codebook) or when it abstained (coded mechanically by the pipeline's failure name, D-040
             item 4, never recoded). Correct roots (TP, TN) are shown for context and are not items. Each
             section carries what a coder needs: the fix's source diff from the project clone, the
             decompiled root before and after the fix (addresses normalised as in screen S5), each side's
             verdict, reason and unguarded sinks, every rung's outcome for the pair, and, for each item,
             its raw pseudo-C and the callee block of the prompt that produced its final summary (the last
             fixed-point pass when the root is recursive).
             Writes <out>/worksheet.md, <out>/labels.template.json and <out>/items.json.
  tally      Checks a filled labels file against the codebook and against the items re-derived from
             real.json, then writes <out>/gap.json and <out>/gap.md: counts by cell and code, and every
             coded root with its note.

Codebook (pre-registered): D-032's, plus the two categories D-035 found missing ("rand() treated as
trusted", "declined a correct callee verdict"), plus two for real code ("abstained: context overflow",
"root only lacks a check"). D-035's two and "root only lacks a check" describe a missed flaw, so they are
FN codes; Phase 8 observed both of D-035's only on false negatives. Abstentions take the mechanical code.
D-035's tie-break rules apply. Coding is AI-assisted and author-reviewed, disclosed as D-035 requires.

usage: python -m taintwalk.eval.real_gap worksheet
       python -m taintwalk.eval.real_gap tally --labels runs/p9-real/eval/gap/labels.json
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from taintwalk.analysis.prompts import CALLEE_HEADER
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.eval.erroranalysis import CODEBOOK as D032_CODEBOOK
from taintwalk.eval.real_score import RUNGS, SHORT
from taintwalk.eval.score import _table

GAP_VERSION = 1
CODEBOOK: dict[str, tuple[str, ...]] = {
    "FP": tuple(D032_CODEBOOK["FP"]),
    "FN": (*(c for c in D032_CODEBOOK["FN"] if c != "other"), "rand() treated as trusted",
           "declined a correct callee verdict", "root only lacks a check", "other"),
}
ABSTAIN_CODES = {"context_overflow": "abstained: context overflow"}
TIE_BREAKS = (
    "context-induced: for an FP, the model inherited a callee's vulnerable verdict, even when the root passes a "
    "constant; for an FN, a callee summary was wrong (a lost flow or sink, or a false guard) and the model relied "
    "on it. \"ignored constant argument\" is used only when a constant reaches a sink in the root's own code.",
    "other: no category fits; the note names the pattern.",
)
NORMALISE = re.compile(r"_[0-9a-f]{8,16}\b")
SOURCE_DIFF_MAX = 200
CORRECT = ("TP", "TN")


class GapError(RuntimeError):
    """The inputs or the labels do not line up; nothing is written."""


# ---- items ------------------------------------------------------------------------------------

def mechanical_code(reason: str) -> str:
    return ABSTAIN_CODES.get(reason, f"abstained: {reason}")


def items_of(score: dict[str, Any]) -> list[dict[str, Any]]:
    """Every root whose R5 cell is not TP or TN, pre before post within a pair."""
    out: list[dict[str, Any]] = []
    for r in score["roots"]:
        cell = r["cells"]["R5"]
        if cell in CORRECT:
            continue
        item = {"id": f"{r['pair_id']}/{r['side']}", "pair_id": r["pair_id"], "side": r["side"],
                "case_id": r["case_id"], "addr": r["addr"], "cell": cell, "mechanical": None}
        if r["outcomes"]["R5"] == "abstain":
            why = r["abstain_reason"]["R5"]
            if not why:
                raise GapError(f"{item['id']}: abstained with no recorded reason")
            item["mechanical"] = mechanical_code(why)
        elif cell not in CODEBOOK:
            raise GapError(f"{item['id']}: unexpected R5 cell {cell!r}")
        out.append(item)
    return sorted(out, key=lambda i: (i["pair_id"], i["side"] != "pre"))


# ---- what a coder reads -----------------------------------------------------------------------

def source_diff(src_root: Path, project: str, fix: str) -> str:
    """The fix commit's diff of C files, from the project clone; a note instead when it cannot be read."""
    repo = Path(src_root) / project
    if not (repo / ".git").exists():
        return f"(no clone at {repo})"
    p = subprocess.run(["git", "-C", str(repo), "show", "--no-color", "--format=commit %H%n%s", fix, "--", "*.c"],
                       capture_output=True, text=True, check=False)
    if p.returncode != 0:
        return f"(git show {fix[:12]} failed: {p.stderr.strip()[:200]})"
    lines = p.stdout.rstrip("\n").splitlines()
    if len(lines) > SOURCE_DIFF_MAX:
        lines = lines[:SOURCE_DIFF_MAX] + [f"... ({len(lines) - SOURCE_DIFF_MAX} more lines)"]
    return "\n".join(lines)


def pseudo_diff(pre: str | None, post: str | None) -> str:
    a = NORMALISE.sub("_", pre or "").splitlines()
    b = NORMALISE.sub("_", post or "").splitlines()
    return "\n".join(difflib.unified_diff(a, b, "pre-fix root", "post-fix root", n=2, lineterm="")) or "(identical)"


def _walk_dirs(walk_root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for p in sorted(Path(walk_root).glob("*/walk.json")):
        out[json.loads(p.read_text(encoding="utf-8"))["binary_sha256"]] = p.parent
    return out


def side_view(run_dir: Path, addr: str) -> dict[str, Any]:
    """The final R5 row of one root, from walk.json, summaries.json and the prompt that produced it."""
    walk = json.loads((run_dir / "walk.json").read_text(encoding="utf-8"))
    summaries = json.loads((run_dir / "summaries.json").read_text(encoding="utf-8"))
    if addr not in walk["functions"]:
        raise GapError(f"{run_dir.name}: {addr} was not walked")
    fn = walk["functions"][addr]
    tag = fn.get("tag") or ""
    prompt = run_dir / "prompts" / f"{walk['binary_sha256'][:12]}_{addr}{tag}.json"
    block = ""
    if prompt.exists():
        user = json.loads(prompt.read_text(encoding="utf-8"))["user"]
        i = user.find(CALLEE_HEADER)
        block = user[i:].strip() if i >= 0 else ""
    return {"function": fn["function"], "status": fn["status"], "failure": fn.get("failure"),
            "iteration": fn.get("iteration", 0), "context_chars": fn.get("context_chars", 0),
            "callees": len(fn.get("callees", [])), "omitted": len(fn.get("omitted", [])),
            "callee_views": dict(sorted(Counter((fn.get("callee_statuses") or {}).values()).items())),
            "record": summaries.get(addr), "callee_block": block}


def _verdict_lines(v: dict[str, Any]) -> list[str]:
    rec = v["record"]
    if rec is None:
        return [f"- no summary: {v['failure'] or v['status']}"]
    vd = rec["summary"]["verdict"]
    sinks = [s for s in rec["summary"]["sinks"] if not s["guarded"]]
    return [f"- verdict: vulnerable {vd['vulnerable']}; {vd['mechanism']} / {vd['region']} / {vd['access']} / "
            f"{vd['direction']}; confidence {vd['confidence']}",
            f"- reason: {vd['reason']}",
            "- unguarded sinks: " + ("; ".join(f"line {s['evidence_line']} {s['sink_kind']} {s['callee']}".rstrip()
                                                for s in sinks) or "none")]


def worksheet(score: dict[str, Any], manifest: dict[str, Any], *, walk_root: Path, programs_dir: Path,
              src_root: Path) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    """The worksheet text, the items, and the labels template. Deterministic."""
    items = items_of(score)
    by_id = {i["id"]: i for i in items}
    pairs_m = {p["pair_id"]: p for p in manifest["pairs"]}
    dirs = _walk_dirs(walk_root)
    progs: dict[str, dict[str, dict[str, Any]]] = {}
    hand = sum(i["mechanical"] is None for i in items)
    lines = ["# Phase 9 gap-analysis worksheet (R5)", "",
             "Coding is AI-assisted and author-reviewed (pre-registration; D-035). Give every root marked "
             "`code: ____` exactly one codebook entry and a one-line note. Abstentions are coded mechanically "
             "(D-040 item 4) and are already filled in.", "",
             "## Codebook (pre-registered)", ""]
    lines += [f"- {cell}: " + "; ".join(f"`{c}`" for c in codes) for cell, codes in CODEBOOK.items()]
    lines += ["- abstained (mechanical): `abstained: context overflow`, or `abstained: <failure name>` "
              "for any other failure (for example `abstained: max_tokens`)", "",
              "Tie-break rules (D-035):", ""] + [f"- {t}" for t in TIE_BREAKS]
    lines += ["", f"{len(score['pairs'])} pairs; {len(items)} items: {hand} to hand-code, "
              f"{len(items) - hand} mechanical. Correct roots are shown for context only."]

    for p in score["pairs"]:
        pm = pairs_m.get(p["pair_id"])
        if pm is None:
            raise GapError(f"{p['pair_id']} is not in the manifest")
        lines += ["", f"## {p['pair_id']} {p['cve']} {p['project']} {p['function']}: R5 {p['outcomes']['R5']}", "",
                  f"- fix {pm['fix'][:12]} in {p['project']}, file {pm['file']}",
                  "- every rung, pre/post: " + ", ".join(f"{k} {SHORT[p['pre'][k]]}/{SHORT[p['post'][k]]}"
                                                        for k in RUNGS),
                  f"- no callee block at either root: {'yes' if p['no_callee'] else 'no'}",
                  "", "### Source diff of the fix", "", "```diff", source_diff(src_root, p["project"], pm["fix"]),
                  "```"]
        texts: dict[str, str | None] = {}
        for side in ("pre", "post"):
            case, addr = pm[side], pm[f"{side}_addr"]
            if case not in progs:
                prog = json.loads((Path(programs_dir) / f"{case}.json").read_text(encoding="utf-8"))
                progs[case] = {f["addr"]: f for f in prog["functions"]}
            texts[side] = progs[case][addr].get("pseudo_c")
        lines += ["", "### Decompiled root, pre to post (addresses normalised)", "", "```diff",
                  pseudo_diff(texts["pre"], texts["post"]), "```"]
        for side, label in (("pre", "bad"), ("post", "good")):
            case, addr = pm[side], pm[f"{side}_addr"]
            root = next(r for r in score["roots"] if r["pair_id"] == p["pair_id"] and r["side"] == side)
            sha = root["binary_sha256"]
            if sha not in dirs:
                raise GapError(f"{p['pair_id']} {side}: no walk run dir for {case}")
            v = side_view(dirs[sha], addr)
            item = by_id.get(f"{p['pair_id']}/{side}")
            lines += ["", f"### {side} ({label}) {case} {addr} {v['function']}: R5 {root['cells']['R5']}", ""]
            lines += _verdict_lines(v)
            lines.append(f"- callee block {v['context_chars']} chars: {v['callees']} callees, {v['omitted']} omitted "
                         f"(budget); callee views {v['callee_views'] or '{}'}; final pass {v['iteration']}")
            if item is None:
                continue
            lines.append(f"- code: `{item['mechanical']}` (mechanical)" if item["mechanical"]
                         else "- code: ____   note: ____")
            lines += ["", "Raw pseudo-C (the model saw it after zero-fill collapse and literal redaction):", "",
                      "```c", (texts[side] or "").rstrip(), "```"]
            if v["callee_block"]:
                lines += ["", "Callee block in the prompt that produced the final summary:", "",
                          "```", v["callee_block"], "```"]
    template = {"gap_version": GAP_VERSION, "rung": "R5",
                "items": {i["id"]: {"code": i["mechanical"], "note": ""} for i in items}}
    return "\n".join(lines) + "\n", items, template


# ---- tally ------------------------------------------------------------------------------------

def tally(items: list[dict[str, Any]], labels: dict[str, Any]) -> dict[str, Any]:
    lab = labels.get("items")
    if not isinstance(lab, dict):
        raise GapError("labels file has no 'items' object")
    ids = [i["id"] for i in items]
    missing, extra = sorted(set(ids) - set(lab)), sorted(set(lab) - set(ids))
    if missing or extra:
        raise GapError(f"labels do not match the items: missing {missing[:5]}, extra {extra[:5]}")
    rows: list[dict[str, Any]] = []
    for i in items:
        e = lab[i["id"]] or {}
        code, note = e.get("code"), str(e.get("note") or "").strip()
        if i["mechanical"]:
            if code != i["mechanical"]:
                raise GapError(f"{i['id']}: an abstention is coded mechanically as {i['mechanical']!r}, not {code!r}")
        else:
            if code not in CODEBOOK[i["cell"]]:
                raise GapError(f"{i['id']} ({i['cell']}): {code!r} is not a {i['cell']} code")
            if not note:
                raise GapError(f"{i['id']}: every hand-coded root needs a one-line note")
        rows.append({**i, "code": code, "note": note})
    counts = {cell: dict(sorted(Counter(r["code"] for r in rows if r["cell"] == cell).items()))
              for cell in sorted({r["cell"] for r in rows})}
    return {"gap_version": GAP_VERSION, "rung": "R5", "items": rows, "counts": counts,
            "hand_coded": sum(r["mechanical"] is None for r in rows),
            "mechanical": sum(r["mechanical"] is not None for r in rows)}


def render_tally(g: dict[str, Any]) -> str:
    lines = ["## R5 errors at the roots, coded", "",
             f"{g['hand_coded']} hand-coded (AI-assisted, author-reviewed, D-035) and {g['mechanical']} abstentions "
             "coded mechanically (D-040 item 4).", ""]
    lines += _table(["cell", "code", "roots"],
                    [[cell, code, n] for cell, codes in g["counts"].items() for code, n in codes.items()], md=True)
    lines += ["", *_table(["item", "binary", "addr", "cell", "code", "note"],
                          [[r["id"], r["case_id"], r["addr"], r["cell"], r["code"], r["note"] or "-"]
                           for r in g["items"]], md=True)]
    return "\n".join(lines) + "\n"


# ---- command line -----------------------------------------------------------------------------

def _abs(p: str) -> Path:
    q = Path(p)
    return q if q.is_absolute() else REPO_ROOT / q


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m taintwalk.eval.real_gap",
                                 description="Phase 9 gap analysis: the R5 worksheet, then the tally of the coding.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("worksheet", "tally"):
        s = sub.add_parser(name)
        s.add_argument("--score", default="runs/p9-real/eval/real.json")
        s.add_argument("--out", default="runs/p9-real/eval/gap")
        if name == "worksheet":
            s.add_argument("--manifest", help="real-code manifest (default: config real.manifest)")
            s.add_argument("--walk", default="runs/p9-real/walk")
            s.add_argument("--programs", default="runs/p9-real/programs")
            s.add_argument("--src", default="runs/p9-spike/src", help="project clones, <src>/<project>")
        else:
            s.add_argument("--labels", required=True)
    args = ap.parse_args(argv)
    out = _abs(args.out)
    try:
        score = json.loads(_abs(args.score).read_text(encoding="utf-8"))
        if args.cmd == "worksheet":
            mpath = _abs(args.manifest) if args.manifest else REPO_ROOT / load_config()["real"]["manifest"]
            text, items, template = worksheet(score, json.loads(mpath.read_text(encoding="utf-8")),
                                              walk_root=_abs(args.walk), programs_dir=_abs(args.programs),
                                              src_root=_abs(args.src))
            _write(out / "worksheet.md", text)
            _write(out / "items.json", json.dumps(items, indent=1, sort_keys=True) + "\n")
            _write(out / "labels.template.json", json.dumps(template, indent=1, sort_keys=True) + "\n")
            hand = sum(i["mechanical"] is None for i in items)
            print(f"worksheet          : {out / 'worksheet.md'}")
            print(f"labels template    : {out / 'labels.template.json'} (copy to labels.json and fill in)")
            print(f"GAP WORKSHEET OK: {len(items)} items, {hand} to hand-code, {len(items) - hand} mechanical")
        else:
            g = tally(items_of(score), json.loads(_abs(args.labels).read_text(encoding="utf-8")))
            _write(out / "gap.json", json.dumps(g, indent=1, sort_keys=True) + "\n")
            _write(out / "gap.md", render_tally(g))
            print(render_tally(g), end="")
            print(f"GAP TALLY OK: {len(g['items'])} items, {g['hand_coded']} hand-coded, {g['mechanical']} mechanical")
    except (GapError, OSError, ValueError, KeyError) as e:
        print(f"GAP FAIL: {type(e).__name__}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())