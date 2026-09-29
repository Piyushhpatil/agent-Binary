"""`taintwalk score`: D-008 scoring of walk run dirs, printed and written (Phase 7, eval side).

Reads persisted files only. For every run dir it rebuilds findings.json from walk.json and
summaries.json (analysis/findings.py, label-free), joins them to ground truth (eval/metrics.py),
and writes <root>/eval/score.json with sorted keys and no timestamps, so an unchanged input gives a
byte-identical file. It never constructs a provider; as a check it refuses to pass if any
taintwalk.llm module was loaded in the process.

--results-md renders the same tables as Markdown. D-028: in Phase 7 it is written under the run
dir, never to docs/RESULTS.md, and its status line says the numbers are not reportable.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from taintwalk.analysis.findings import FindingsError, write_findings
from taintwalk.eval.metrics import LEVELS, STRATA, ScoreError, dumps_score, score_runs

DEFAULT_STATUS = ("DEVELOPMENT OBSERVATION: scorer shakedown data, not a reportable result (D-028). "
                  "Headline numbers come from Phase 8 only.")
GROUPS = (*STRATA, "pooled")
CONF_HEADER = ["roots", "TP", "FN", "FN_abs", "FP", "TN", "abstain",
               "precision", "recall", "specificity", "coverage", "F1"]
WRONG_KEYS = ("ambiguous", "right_mechanism_wrong_field", "wrong_mechanism", "total")


def discover_runs(root: Path) -> list[Path]:
    """A walk run dir itself, or every direct subdirectory holding a walk.json, sorted."""
    root = Path(root)
    if (root / "walk.json").exists():
        return [root]
    return [p.parent for p in sorted(root.glob("*/walk.json"))]


def _r(rate: dict[str, Any]) -> str:
    if rate["value"] is None:
        return "-"
    lo, hi = rate["ci95"]
    return f"{rate['value']:.3f} [{lo:.3f},{hi:.3f}] {rate['k']}/{rate['n']}"


def _x(v: float | None) -> str:
    return "-" if v is None else f"{v:.3f}"


def _table(header: list[str], rows: list[list[Any]], *, md: bool) -> list[str]:
    cells = [[str(c) for c in header]] + [[str(c) for c in r] for r in rows]
    if md:
        return (["| " + " | ".join(cells[0]) + " |", "|" + "|".join("---" for _ in header) + "|"]
                + ["| " + " | ".join(r) + " |" for r in cells[1:]])
    w = [max(len(r[i]) for r in cells) for i in range(len(header))]
    return ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip() for r in cells]


def _conf_cells(c: dict[str, Any]) -> list[Any]:
    k = c["cells"]
    return [c["roots"], k["TP"], k["FN"], k["FN_abstain"], k["FP"], k["TN"], k["abstain"],
            _r(c["precision"]), _r(c["recall"]), _r(c["specificity"]), _r(c["coverage"]), _x(c["f1"])]


def sections(score: dict[str, Any]) -> list[tuple[str, list[str], list[list[Any]]]]:
    st = score["strata"]
    out: list[tuple[str, list[str], list[list[Any]]]] = []
    for key, title in (("primary", "PRIMARY: path roots (D-008)"),
                       ("secondary", "SECONDARY: any member of the path (never the headline)")):
        out.append((title, ["stratum", *CONF_HEADER], [[g, *_conf_cells(st[g][key])] for g in GROUPS]))
    out.append(("TYPED LADDER at the root (precision = typed TPs / all root findings)",
                ["stratum", "root findings", "level", "TP", "precision", "recall", "F1"],
                [[g, st[g]["typed"]["root_findings"], lvl, st[g]["typed"][lvl]["tp"],
                  _r(st[g]["typed"][lvl]["precision"]), _r(st[g]["typed"][lvl]["recall"]),
                  _x(st[g]["typed"][lvl]["f1"])] for g in GROUPS for lvl in LEVELS]))
    out.append(("RIGHT BUG, WRONG CWE (detected bad roots that miss the exact class)",
                ["stratum", "ambiguous", "right mechanism, wrong field", "wrong mechanism", "total"],
                [[g, *(st[g]["typed"]["right_bug_wrong_cwe"][k] for k in WRONG_KEYS)] for g in GROUPS]))
    for key, title, col in (("by_class", "BY CLASS (primary; D-011: never class x flow)", "class"),
                            ("by_flow", "BY FLOW VARIANT (primary, pooled over classes)", "flow")):
        out.append((title, ["stratum", col, *CONF_HEADER],
                    [[g, k, *_conf_cells(c)] for g in GROUPS for k, c in score[key][g].items()]))
    out.append(("CONFIDENCE (S2): AUROC = ranking, ECE = calibration; answered roots only",
                ["stratum", "answered", "AUROC", "ECE"],
                [[g, st[g]["confidence"]["answered"], _x(st[g]["confidence"]["auroc"]),
                  _x(st[g]["confidence"]["ece"])] for g in GROUPS]))
    out.append(("RELIABILITY BINS", ["stratum", "bin", "n", "mean score", "fraction bad"],
                [[g, f"[{b['bin'][0]:.1f},{b['bin'][1]:.1f})", b["n"], _x(b["mean_score"]),
                  _x(b["fraction_bad"])] for g in GROUPS for b in st[g]["confidence"]["bins"]]))
    out.append(("DIAGNOSTICS: walked functions outside the scored roots (never in precision/recall)",
                ["label/role", "walked", "flagged", "clear", "abstain"],
                [[k, v["n"], v["flagged"], v["clear"], v["abstain"]] for k, v in score["diagnostics"].items()]))
    return out


def _identity_lines(score: dict[str, Any]) -> list[str]:
    p, pooled = score["provider"], score["strata"]["pooled"]["primary"]
    return [
        f"binaries           : {len(score['inputs'])}  path roots {pooled['roots']} "
        f"({pooled['positives']} bad, {pooled['negatives']} good)",
        f"provider           : {p.get('provider')}  model {p.get('model')}  digest {p.get('digest', '-')}  "
        f"prompt v{score['prompt_version']}  callee context v{score['callee_context_version']}",
        f"roots not walked   : {score['roots_not_walked']}   [must be 0]",
        f"no summary         : {sum(i['no_summary'] for i in score['inputs'])} walked functions "
        "(an abstention when at a root)",
    ]


def render_report(score: dict[str, Any], *, full: bool) -> list[str]:
    lines = _identity_lines(score)
    secs = sections(score)
    for title, header, rows in (secs if full else secs[:1]):
        lines += ["", title, *_table(header, rows, md=False)]
    return lines + [""]


def render_markdown(score: dict[str, Any], status: str) -> list[str]:
    lines = ["# TaintWalk scoring results", "", f"> **Status:** {status}", "",
             *[f"- {line}" for line in _identity_lines(score)],
             f"- binaries scored: {', '.join(i['case_id'] for i in score['inputs'])}",
             "- rules: D-008 (path-root attribution, secondary any-member rule, typed ladder, abstention)"]
    for title, header, rows in sections(score):
        lines += ["", f"## {title}", "", *_table(header, rows, md=True)]
    return lines


def run_score(root: Path, *, labels_dir: Path, programs_dir: Path, report: bool = False,
              results_md: Path | None = None, status: str | None = None) -> int:
    from taintwalk.extract.report import load_manifest

    root = Path(root)
    runs = discover_runs(root)
    if not runs:
        print(f"SCORE FAIL: no walk run dir at or under {root}")
        return 1
    try:
        for d in runs:
            write_findings(d)
        score = score_runs(runs, manifest=load_manifest(), labels_dir=labels_dir, programs_dir=programs_dir)
    except (ScoreError, FindingsError) as e:
        print(f"SCORE FAIL: {type(e).__name__}: {e}")
        return 1
    out = root / "eval" / "score.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dumps_score(score), encoding="utf-8")
    for line in render_report(score, full=report):
        print(line)
    if results_md is not None:
        md = Path(results_md)
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text("\n".join(render_markdown(score, status or DEFAULT_STATUS)) + "\n", encoding="utf-8")
        print(f"results markdown   : {md}")
    loaded = sorted(m for m in sys.modules if m == "taintwalk.llm" or m.startswith("taintwalk.llm."))
    print(f"llm calls          : 0 (persisted files only); provider modules loaded: {', '.join(loaded) or 'none'}")
    print(f"findings           : {len(runs)} findings.json rewritten (label-free)")
    print(f"score.json         : {out}")
    ok = score["roots_not_walked"] == 0 and not loaded
    print("SCORE OK" if ok else "SCORE FAIL")
    return 0 if ok else 1