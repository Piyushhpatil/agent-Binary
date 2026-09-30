"""`taintwalk eval` (Phase 8, D-032, D-034): score every rung, run the pre-registered tests, write RESULTS.md.

Reads persisted files only; the walks happen elsewhere (`taintwalk walk --all`). Steps:
  1. --replay-check: replay each walk root offline into <out>/replay/<provider> (a separate root, so
     the live run's walk_all.json, logs and usage.json survive) and require byte-identical summaries.json;
  2. R1-R3 from program.json (eval/baselines.py), written to <out>/rules/;
  3. R4-R7 from the walk roots; every rung scored by score_rung() into <out>/scores/<rung>.json;
  4. the pre-registered tests and, per provider, the ablation by stratum (eval/ablation.py). Without a
     cloud root the report is local-only (D-034): rungs R1-R5, family C2/C3L/C4L; with one, D-030's 10 tests;
  5. error analysis (eval/erroranalysis.py): parroting, the sanitizer-literal shortcut and abstentions for
     every LLM rung, and the hand-coding worksheet of the headline walk rung into <out>/errors/;
  6. cost from cache entries and runtime from the live walk_all.json (eval/cost.py);
  7. <out>/eval.json and RESULTS.md, rendered from those, with docs/ERROR-ANALYSIS.md verbatim.
No timestamps anywhere, so an unchanged input rewrites byte-identical files. The command-line entry
fails if a taintwalk.llm module was loaded in its process: nothing here may call a model.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from taintwalk.analysis.findings import FindingsError
from taintwalk.config import REPO_ROOT
from taintwalk.eval.ablation import (
    COMPARISONS,
    LABELS,
    LOCAL_COMPARISONS,
    AblationError,
    ablation,
    preregistered_tests,
    root_contexts,
    strata_of_roots,
)
from taintwalk.eval.baselines import RungError, llm_rung_doc, rule_rung_docs, write_doc
from taintwalk.eval.cost import PRICES_AS_OF, CostError, cost_report
from taintwalk.eval.erroranalysis import (
    PARROT_MIN_WORDS,
    ErrorAnalysisError,
    abstention_kinds,
    arm_reasons,
    literal_shortcut,
    parroting,
    worksheet,
)
from taintwalk.eval.metrics import LEVELS, STRATA, ScoreError, dumps_score, score_rung
from taintwalk.eval.score import _r, _table, _x, discover_runs
from taintwalk.extract.report import load_manifest

RUNGS = ("R1", "R2", "R3", "R4", "R5", "R6", "R7")
LOCAL_RUNGS = RUNGS[:5]
NAMES = {"R1": "flawfinder", "R2": "input rule", "R3": "reachability of an R1 hit",
         "R4": "per-function LLM, local", "R5": "TaintWalk, local",
         "R6": "per-function LLM, cloud", "R7": "TaintWalk, cloud (headline)"}
PROVIDERS = (("local", "ollama", "R5", "R4"), ("cloud", "anthropic", "R7", "R6"))
FAMILIES = {"cloud": ("D-030: C1-C5 on bad and good roots, 10 tests", COMPARISONS),
            "local": ("D-034 local-only: C2, C3L, C4L on bad and good roots, 6 tests", LOCAL_COMPARISONS)}
EXPECTED_ROOTS = 636
DEFAULT_STATUS = "DRAFT: development run, not the Phase 8 gate (D-032)."
DISCLOSED_BINARIES = ("tw-0015", "tw-0022", "tw-0065", "tw-0066", "tw-0091", "tw-0125", "tw-0135",
                      "tw-0151", "tw-0166", "tw-0175", "tw-0178", "tw-0188", "tw-0237")
LIMITATIONS = (
    "Juliet is synthetic and stylized; every claim here is provisional until Phase 9 measures real code.",
    "Frozen pipeline (D-032): no grounding rule for rendered callee fields, `.rodata` strings unresolved, "
    "alloca probe loops not collapsed.",
    "R1's statically-sized-array rule fires on `char buf[N]` but not on `undefined1 buf[N]`, so part of its "
    "recall depends on the decompiler's type recovery, not on flawfinder.",
    "`rand()` counts as an input source (Juliet's convention, the prompt's, and R2's list).",
    "CWE-78, 134 and 606 are effectively char-only: their wchar_t variants did not compile (D-013).",
    "Flow 44's function pointers resolve to call edges at -O0; an unresolved computed call would give no edge.",
)
LOCAL_ONLY_LIMITATION = ("Local 9B model only: the cloud headline (R7) is deferred pending API funding (D-034), "
                         "so every LLM number here comes from ornith:9b.")
FUTURE_WORK = (
    "Cloud rungs R6/R7 on Claude Sonnet 5.5 are deferred until the API is funded (D-034). Everything they need is "
    "built and tested offline: the D-031 configuration is in `config/providers.yaml`, and `taintwalk eval --cloud "
    "ROOT` adds them.",
    "Once funded: G-CLOUD pings, the label-free 40-function probe and its cost rule (D-031), the full cloud walk "
    "with `--with-baseline`, then the full family of 10 pre-registered tests (D-030) and the provider comparison.",
)


# ---- steps --------------------------------------------------------------------------------

def _summaries_by_sha(root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for d in discover_runs(Path(root)):
        out[json.loads((d / "walk.json").read_text(encoding="utf-8"))["binary_sha256"]] = d / "summaries.json"
    return out


def _replay_check(root: Path, provider: str, programs_dir: Path, replay_root: Path, name: str,
                  jobs: int) -> dict[str, Any]:
    """Offline replay into a separate root; count run dirs whose summaries.json is byte-identical."""
    target = replay_root / name
    shutil.rmtree(target, ignore_errors=True)
    replay_root.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "taintwalk.cli", "walk", "--all", "--programs", str(programs_dir),
           "--run-dir", str(target), "--provider", provider, "--with-baseline", "--offline", "--jobs", str(jobs)]
    with (replay_root / f"{name}.log").open("w", encoding="utf-8") as fh:
        rc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                            check=False).returncode
    live, again = _summaries_by_sha(root), _summaries_by_sha(target)
    same = sum(1 for sha, p in live.items() if sha in again and again[sha].read_bytes() == p.read_bytes())
    return {"rc": rc, "programs": len(live), "replayed": len(again), "identical": same}


def _rung_docs(roots: dict[str, Path], programs_dir: Path, out_dir: Path) -> dict[str, dict[str, Any]]:
    docs = rule_rung_docs(programs_dir, out_dir / "rules")
    for k, d in docs.items():
        write_doc(d, out_dir / "rules" / f"{k}.json")
    for name, _, walk_rung, base_rung in PROVIDERS:
        if name in roots:
            docs[walk_rung] = llm_rung_doc(roots[name], walk_rung)
            docs[base_rung] = llm_rung_doc(roots[name], base_rung)
    return docs


def _score_all(docs: dict[str, dict[str, Any]], *, labels_dir: Path, programs_dir: Path,
               out_dir: Path) -> dict[str, dict[str, Any]]:
    manifest = load_manifest()
    scores: dict[str, dict[str, Any]] = {}
    (out_dir / "scores").mkdir(parents=True, exist_ok=True)
    for rung in RUNGS:
        if rung in docs:
            s = score_rung(docs[rung], manifest=manifest, labels_dir=labels_dir, programs_dir=programs_dir)
            (out_dir / "scores" / f"{rung}.json").write_text(dumps_score(s), encoding="utf-8")
            scores[rung] = s
    return scores


def _problems(scores: dict[str, dict[str, Any]], *, full: bool, required: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    keysets = {r: tuple(sorted((x["case_id"], x["addr"]) for x in s["roots"])) for r, s in scores.items()}
    if len(set(keysets.values())) > 1:
        out.append("rungs score different root sets")
    out += [f"{r}: {s['roots_not_walked']} roots not walked" for r, s in scores.items() if s["roots_not_walked"]]
    if full:
        out += [f"{r} missing" for r in required if r not in scores]
        out += [f"{r}: {len(s['roots'])} roots, expected {EXPECTED_ROOTS}"
                for r, s in scores.items() if len(s["roots"]) != EXPECTED_ROOTS]
    return out


def _ablations(scores: dict[str, dict[str, Any]], roots: dict[str, Path]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, _, walk_rung, base_rung in PROVIDERS:
        if name in roots and walk_rung in scores and base_rung in scores:
            strata = strata_of_roots(scores[walk_rung]["roots"], root_contexts(roots[name]))
            out[name] = ablation(scores[walk_rung]["roots"], scores[base_rung]["roots"], strata)
    return out


def _error_measures(scores: dict[str, dict[str, Any]], roots: dict[str, Path], programs_dir: Path,
                    out_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Automated measures for every LLM rung present, and the worksheet of the headline walk rung."""
    errors: dict[str, Any] = {}
    for name, _, walk_rung, base_rung in PROVIDERS:
        if name not in roots:
            continue
        for rung, arm in ((walk_rung, "walk"), (base_rung, "baseline")):
            if rung in scores:
                errors[rung] = {"parroting": parroting(arm_reasons(roots[name], arm)),
                                "literal_shortcut": literal_shortcut(scores[rung], programs_dir),
                                "abstentions": abstention_kinds(roots[name], arm)}
    sample: dict[str, Any] = {}
    for name, rung in (("cloud", "R7"), ("local", "R5")):
        if name in roots and rung in scores:
            md, sample = worksheet(scores[rung], roots[name], arm="walk", programs_dir=programs_dir)
            (out_dir / "errors").mkdir(parents=True, exist_ok=True)
            (out_dir / "errors" / f"worksheet-{rung}.md").write_text(md, encoding="utf-8")
            break
    return errors, sample


def _runtime(root: Path) -> dict[str, Any] | None:
    p = Path(root) / "walk_all.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    out = {k: d.get(k) for k in ("programs", "walk_ok", "calls", "cache_hits", "tokens_in", "tokens_out",
                                 "model_s", "wall_s")}
    out["run_dirs"] = len(discover_runs(Path(root)))
    return out


def run_eval(*, local_root: Path | None, cloud_root: Path | None, programs_dir: Path, labels_dir: Path,
             out_dir: Path, results_md: Path | None, status: str = DEFAULT_STATUS,
             error_analysis: Path | None = None, replay_check: bool = False, jobs: int = 4,
             full: bool = False) -> tuple[int, dict[str, Any]]:
    """Everything except the provider-module check (run_from_args adds it). Returns (rc, eval doc)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    roots = {n: Path(r) for n, r in (("local", local_root), ("cloud", cloud_root)) if r is not None}
    mode = "cloud" if "cloud" in roots else "local"
    family_name, family = FAMILIES[mode]
    problems: list[str] = []
    replay: dict[str, Any] = {}
    try:
        if replay_check:
            for name, provider, _, _ in PROVIDERS:
                if name in roots:
                    r = _replay_check(roots[name], provider, Path(programs_dir), out_dir / "replay", name, jobs)
                    replay[name] = r
                    if r["rc"] != 0 or r["identical"] != r["programs"]:
                        problems.append(f"{name} replay: exit {r['rc']}, summaries.json identical "
                                        f"{r['identical']}/{r['programs']}")
        docs = _rung_docs(roots, Path(programs_dir), out_dir)
        scores = _score_all(docs, labels_dir=Path(labels_dir), programs_dir=Path(programs_dir), out_dir=out_dir)
        problems += _problems(scores, full=full, required=RUNGS if mode == "cloud" else LOCAL_RUNGS)
        tests = preregistered_tests({r: s["roots"] for r, s in scores.items()}, comparisons=family)
        tests["family_name"] = family_name
        abl = _ablations(scores, roots)
        errors, sample = _error_measures(scores, roots, Path(programs_dir), out_dir)
        cost = {n: cost_report(root) for n, root in sorted(roots.items())}
    except (RungError, ScoreError, AblationError, CostError, FindingsError, ErrorAnalysisError) as e:
        print(f"EVAL ERROR: {type(e).__name__}: {e}")
        return 1, {}
    ev = {
        "rungs": {r: {"kind": s["kind"], "score_scale": s["score_scale"], "definition": s["definition"],
                      "identity": s["identity"], "roots": len(s["roots"]),
                      "primary": s["strata"]["pooled"]["primary"]} for r, s in scores.items()},
        "cloud_deferred": mode == "local",
        "tests": tests, "ablation": abl, "errors": errors, "error_sample": sample, "cost": cost,
        "runtime": {n: _runtime(r) for n, r in sorted(roots.items())},
        "replay": replay, "problems": problems,
    }
    (out_dir / "eval.json").write_text(json.dumps(ev, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    if results_md is not None:
        text = None
        if error_analysis is not None and Path(error_analysis).exists():
            text = Path(error_analysis).read_text(encoding="utf-8")
        md = Path(results_md)
        md.parent.mkdir(parents=True, exist_ok=True)
        md.write_text(render_results(ev, scores, status=status, error_text=text), encoding="utf-8")
    print(f"rungs scored       : {' '.join(scores)}  roots per rung {sorted({len(s['roots']) for s in scores.values()})}")
    print(f"pre-registered     : {family_name}: {len(tests['tests'])} of {tests['family']} tests, Holm applied: "
          f"{'yes' if tests['holm_applied'] else 'no (missing ' + ', '.join(tests['missing']) + ')'}")
    for name, a in sorted(abl.items()):
        print(f"ablation {name:<9} : roots per stratum {a['counts']}")
    if sample:
        print(f"error worksheet    : {out_dir / 'errors' / ('worksheet-' + sample['rung'] + '.md')} "
              f"(FP {len(sample['FP'])}, FN {len(sample['FN'])})")
    for name, c in sorted(cost.items()):
        print(f"cost {name:<13} : union {c['arms']['union']['calls']} calls, USD {c['arms']['union']['usd']}")
    for name, r in sorted(replay.items()):
        print(f"replay {name:<11} : exit {r['rc']}, summaries.json identical {r['identical']}/{r['programs']}")
    print(f"eval.json          : {out_dir / 'eval.json'}")
    if results_md is not None:
        print(f"results markdown   : {results_md}")
    for p in problems:
        print(f"PROBLEM: {p}")
    return (0 if not problems else 1), ev


# ---- rendering ------------------------------------------------------------------------------

def _v(rate: dict[str, Any] | None) -> str:
    return "-" if rate is None or rate["value"] is None else f"{rate['value']:.2f}"


def _pair(cell: dict[str, Any] | None) -> str:
    return "-" if cell is None else f"{_v(cell['recall'])} / {_v(cell['specificity'])}"


def render_results(ev: dict[str, Any], scores: dict[str, dict[str, Any]], *, status: str,
                   error_text: str | None) -> str:
    present = [r for r in RUNGS if r in scores]
    pooled = {r: scores[r]["strata"]["pooled"] for r in present}
    deferred = bool(ev.get("cloud_deferred"))
    lines: list[str] = [
        "# TaintWalk results (Phase 8)", "", f"> **Status:** {status}", "",
        f"- Rungs scored: {', '.join(present)}. Every rung is scored by the same D-008 code at the same "
        "path roots (I6).",
        "- Rungs, tests, strata and codebook were fixed before any number existed: `docs/PREREGISTRATION.md`"
        + (" (with Deviation D-034: cloud rungs deferred pending funding)." if deferred else "."),
        "- Every cell with its 95% Wilson interval, and every root row: `scores/<rung>.json` beside `eval.json`.",
    ]

    def block(level: str, title: str, intro: str, header: list[str], rows: list[list[Any]]) -> None:
        lines.extend(["", f"{level} {title}", ""])
        if intro:
            lines.extend([intro, ""])
        lines.extend(_table(header, rows, md=True) if rows else ["_No rows._"])

    def section(title: str, intro: str, header: list[str], rows: list[list[Any]]) -> None:
        block("##", title, intro, header, rows)

    def conf(r: str) -> dict[str, Any]:
        return pooled[r]["confidence"] or {}

    four = ("precision", "recall", "specificity", "coverage")
    section("Main table", "Primary rule: one scored function per path, the path root; pooled over strata.",
            ["rung", "what", *four, "F1", "AUROC"],
            [[r, NAMES[r], *(_r(pooled[r]["primary"][k]) for k in four), _x(pooled[r]["primary"]["f1"]),
              _x(conf(r).get("auroc"))] for r in present])
    section("By stratum", "External-source cases and fixed-sink cases (no untrusted input), reported "
            "separately (D-023).", ["rung", "stratum", *four],
            [[r, g, *(_r(scores[r]["strata"][g]["primary"][k]) for k in four)] for r in present for g in STRATA])
    section("Secondary rule", "A path counts as flagged if any function on it is flagged (the usual "
            "convention). Never the headline.", ["rung", "precision", "recall", "specificity"],
            [[r, *(_r(pooled[r]["secondary"][k]) for k in ("precision", "recall", "specificity"))] for r in present])
    llm = [r for r in present if scores[r]["kind"] == "llm"]
    section("Typed ladder", "LLM rungs only: detection, right mechanism, exact CWE (D-021 table).",
            ["rung", "level", "TP", "precision", "recall"],
            [[r, lvl, pooled[r]["typed"][lvl]["tp"], _r(pooled[r]["typed"][lvl]["precision"]),
              _r(pooled[r]["typed"][lvl]["recall"])] for r in llm for lvl in LEVELS])
    section("Confidence", "AUROC: does the score rank bad roots above good ones (0.5 = no signal). ECE: "
            "calibration, for probability-scale rungs only.", ["rung", "answered", "AUROC", "ECE"],
            [[r, conf(r).get("answered", "-"), _x(conf(r).get("auroc")), _x(conf(r).get("ece"))]
             for r in present if pooled[r]["confidence"]])
    tests = ev["tests"]
    note = ("Holm-Bonferroni over the complete family." if tests["holm_applied"] else
            f"Holm correction not applied: the family is incomplete (missing {', '.join(tests['missing'])}); "
            "raw p values only.")
    section("Pre-registered tests", f"Family {tests.get('family_name', '')}. Exact McNemar on paired roots; right = TP "
            "on bad roots, TN on good roots; an abstention is wrong. " + note,
            ["test", "A", "B", "n", "A right", "B right", "A only", "B only", "p", "p (Holm)", "reject"],
            [[k, t["a"], t["b"], t["n"], t["a_right"], t["b_right"], t["a_only"], t["b_only"], _x(t["p"]),
              _x(t.get("p_holm")), ("yes" if t["reject"] else "no") if "reject" in t else "-"]
             for k, t in sorted(tests["tests"].items())])
    abl_rows = []
    for name, a in sorted(ev["ablation"].items()):
        for part in ("all", "S0", "S1", "S2"):
            if a[part] is None:
                continue
            for label in LABELS:
                x = a[part][label]
                abl_rows.append([name, part, label, x["n"], x["a_right"], x["b_right"], x["a_only"], x["b_only"],
                                 _x(x["p"])])
    counts = "; ".join(f"{n}: S0 {a['counts']['S0']}, S1 {a['counts']['S1']}, S2 {a['counts']['S2']}"
                       for n, a in sorted(ev["ablation"].items())) or "none"
    section("Ablation", "Walk arm (A) against the no-context arm (B): same model, same prompts except the "
            "callee block. S0: no callee block, so both arms are identical by construction; S1: callee block, "
            f"one-member path; S2: multi-member path. Roots per stratum: {counts}.",
            ["provider", "stratum", "label", "n", "A right", "B right", "A only", "B only", "p"], abl_rows)
    if "R5" in present and "R7" in present:
        pc_rows = [[r, NAMES[r], *(_r(pooled[r]["primary"][k]) for k in four)] for r in ("R5", "R7")]
        pc_intro = "The same walk on the local 9B model (R5) and the cloud headline model (R7); C5 tests the difference."
    elif deferred:
        pc_rows = []
        pc_intro = ("Deferred pending API funding (D-034): the cloud rungs R6/R7 have not been run. "
                    "See Future work.")
    else:
        pc_rows = []
        pc_intro = "Needs both R5 and R7; missing: " + ", ".join(r for r in ("R5", "R7") if r not in present) + "."
    section("Provider comparison", pc_intro, ["rung", "what", *four], pc_rows)
    head = next((r for r in ("R7", "R5", "R6", "R4") if r in present), present[-1])
    for key, title, col in (("by_class", "By CWE class", "class"), ("by_flow", "By flow variant", "flow")):
        by = scores[head][key]["pooled"]
        section(title, f"{NAMES[head]} ({head}) with 95% Wilson intervals, then every rung as recall / "
                "specificity. Never class x flow (D-011).", [col, "roots", "recall", "specificity", "precision"],
                [[c, v["roots"], _r(v["recall"]), _r(v["specificity"]), _r(v["precision"])] for c, v in by.items()])
        lines.extend(["", *_table([col, *present], [[c, *(_pair(scores[r][key]["pooled"].get(c)) for r in present)]
                                                    for c in by], md=True)])
    cost_rows = []
    for name, c in sorted(ev["cost"].items()):
        for arm in ("walk", "baseline", "union"):
            a = c["arms"][arm]
            cost_rows.append([name, arm, a["calls"], a["missing_entries"], a["input_tokens"],
                              a.get("cache_write_input_tokens", 0), a["provider_cached_input_tokens"],
                              a["output_tokens"], "-" if a["usd"] is None else f"{a['usd']:.2f}"])
    rt = "; ".join(f"{n}: {r.get('programs')} programs, {r.get('calls')} calls ({r.get('cache_hits')} cache hits), "
                   f"model time {(r.get('model_s') or 0):.0f} s, wall {(r.get('wall_s') or 0):.0f} s"
                   + (f" (the last resumed segment only: {r.get('programs')} of {r.get('run_dirs')} programs; "
                      "earlier segments were interrupted and resumed from the cache)"
                      if r.get("run_dirs") and r.get("programs") != r.get("run_dirs") else "")
                   for n, r in sorted(ev["runtime"].items()) if r) or "no live walk_all.json found"
    section("Cost and runtime", f"Tokens from cache entries (the original calls, deduplicated per arm); dollars at "
            f"{PRICES_AS_OF} list prices. Runtime from the live runs: {rt}.",
            ["provider", "arm", "calls", "missing", "input", "cache write", "cache read", "output", "USD"], cost_rows)
    lines.extend(["", "## Error analysis", ""])
    sample = ev.get("error_sample") or {}
    if sample:
        lines.append(f"Hand-coding sample: {sample['rung']} ({sample['arm']} arm), seed {sample['seed']}: "
                     f"{len(sample['FP'])} false positives and {len(sample['FN'])} false negatives; "
                     "worksheet in `errors/`.")
    errs = ev.get("errors") or {}
    block("###", "Few-shot parroting", f"A reason counts as parroted when it shares {PARROT_MIN_WORDS} or more "
          "consecutive words with a few-shot reason (D-025).", ["rung", "answered", "parroted", "rate"],
          [[r, e["parroting"]["answered"], e["parroting"]["parroted"], _x(e["parroting"]["rate"])]
           for r, e in sorted(errs.items())])
    block("###", "Sanitizer-literal shortcut", "Outcomes at roots whose own pseudo-C holds a sanitizer error "
          "message (D-018), and at the rest.", ["rung", "label", "roots", "n", "flagged", "clear", "abstain"],
          [[r, lab, part.replace("_", " "), c["n"], c["flagged"], c["clear"], c["abstain"]]
           for r, e in sorted(errs.items()) for lab in LABELS for part, c in e["literal_shortcut"][lab].items()])
    block("###", "Abstentions", "Rows with no summary, by failure kind (every walked function, not only roots).",
          ["rung", "failure kinds"],
          [[r, ", ".join(f"{k} {v}" for k, v in e["abstentions"].items()) or "none"] for r, e in sorted(errs.items())])
    lines.extend(["", "### Hand-coded analysis", "",
                  error_text.strip() if error_text else "_Not written yet (mini-step 16)._"])
    lines.extend(["", "## Development-set disclosure", "",
                  "Seen during development and kept in the corpus: " + ", ".join(DISCLOSED_BINARIES)
                  + " (the Phase 6 gate binary and the Phase 7 scorer shakedown), and the Phase 5 development and "
                  "held-out samples (20 functions each), which shaped prompt v2 and the local model choice."])
    lines.extend(["", "## Future work", "",
                  *([f"- {x}" for x in FUTURE_WORK] if deferred
                    else ["- Phase 9: the same pipeline on real open-source binaries."])])
    lines.extend(["", "## Limitations", "",
                  *[f"- {x}" for x in ((LOCAL_ONLY_LIMITATION,) if deferred else ()) + LIMITATIONS]])
    return "\n".join(lines) + "\n"


# ---- command line -----------------------------------------------------------------------------

def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--local", help="walk root of the local model's run: rungs R4 and R5")
    p.add_argument("--cloud", help="walk root of the cloud model's run: rungs R6 and R7")
    p.add_argument("--programs", default="runs/p2-extract/programs", help="dir of program.json files")
    p.add_argument("--labels", default="runs/p2-extract/labels", help="dir of label files")
    p.add_argument("--out", default="runs/p8-eval", help="where rules/, scores/, errors/ and eval.json go")
    p.add_argument("--results-md", help="write RESULTS.md here, e.g. docs/RESULTS.md")
    p.add_argument("--status", default=DEFAULT_STATUS, help="status line at the top of RESULTS.md")
    p.add_argument("--error-analysis", default="docs/ERROR-ANALYSIS.md", help="included verbatim when present")
    p.add_argument("--replay-check", action="store_true",
                   help="replay every walk offline into <out>/replay and require byte-identical summaries.json")
    p.add_argument("--jobs", type=int, default=4, help="parallel programs for the offline replay")
    p.add_argument("--full", action="store_true",
                   help="the Phase 8 gate: every required rung on 636 roots (R1-R5 local-only, D-034; R1-R7 with --cloud)")


def run_from_args(args: argparse.Namespace) -> int:
    def _abs(p: str | None) -> Path | None:
        if p is None:
            return None
        q = Path(p)
        return q if q.is_absolute() else REPO_ROOT / q

    rc, _ = run_eval(local_root=_abs(args.local), cloud_root=_abs(args.cloud), programs_dir=_abs(args.programs),
                     labels_dir=_abs(args.labels), out_dir=_abs(args.out), results_md=_abs(args.results_md),
                     status=args.status, error_analysis=_abs(args.error_analysis),
                     replay_check=args.replay_check, jobs=args.jobs, full=args.full)
    loaded = sorted(m for m in sys.modules if m == "taintwalk.llm" or m.startswith("taintwalk.llm."))
    print(f"llm calls          : 0 in this process; provider modules loaded: {', '.join(loaded) or 'none'}")
    ok = rc == 0 and not loaded
    print("EVAL OK" if ok else "EVAL FAIL")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="taintwalk eval",
                                description="Score every rung, run the pre-registered tests, write RESULTS.md.")
    add_arguments(p)
    return run_from_args(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())