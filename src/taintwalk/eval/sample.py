"""Phase 5 sample selection and verdict agreement (eval side: reads ground truth).

The analysis side receives only runs/<id>/sample.json, which holds (sha256, addr) pairs
and nothing else. The answer key goes to runs/<id>/eval/sample_key.json and is read here
only, after the analysis is done.

Selection rule:
- Flows 01 and 31 only. They are the single-function variants, where the function labeled
  bad actually contains the flaw. In the cross-function flows the flaw can sit in another
  function (D-008, D-013), which a per-function analysis cannot see; that is Phase 6's job.
- bad: role "entry" (the whole flawed function). good: any role except "entry", which in
  these flows is the trivial wrapper that only calls the good variants.
- Half bad, half good, spread over every class: one pick per class per round, alternating
  labels, seeded. With n=20 and 13 classes, every class appears and 7 appear with both labels.
- The final order is shuffled so labels do not alternate by position.
"""
from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from taintwalk.analysis.analyze_one import stem, summary_path

FLOWS = ("01", "31")
DEFAULT_SEED = 20260927


def _pools(labels_dir: Path) -> dict[tuple[str, str], list[dict[str, Any]]]:
    pools: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    files = sorted(Path(labels_dir).glob("tw-*.json"))
    if not files:
        raise ValueError(f"no label files in {labels_dir}; run `taintwalk label ... --report` first")
    for p in files:
        lab = json.loads(p.read_text(encoding="utf-8"))
        if lab["flow_variant"] not in FLOWS:
            continue
        for f in lab["functions"]:
            if not f["scored"]:
                continue
            if f["label"] == "bad" and f["role"] != "entry":
                continue
            if f["label"] == "good" and f["role"] == "entry":
                continue
            pools[(lab["cwe"], f["label"])].append({
                "sha256": lab["program_sha256"], "addr": f["addr"], "case_id": lab["case_id"],
                "cwe": lab["cwe"], "flow_variant": lab["flow_variant"], "label": f["label"],
                "role": f["role"], "name": f["name"],
            })
    for k in pools:
        pools[k].sort(key=lambda r: (r["case_id"], r["addr"]))
    return pools


def select_sample(labels_dir: Path, n: int, seed: int = DEFAULT_SEED) -> tuple[list[dict], list[dict]]:
    """Return (sample, key). sample entries carry exactly sha256 and addr."""
    if n < 2:
        raise ValueError("n must be at least 2")
    rng = random.Random(seed)
    pools = _pools(labels_dir)
    classes = sorted({c for c, _ in pools})
    rng.shuffle(classes)
    want = {"bad": n // 2, "good": n - n // 2}
    picks: list[dict[str, Any]] = []
    rnd, progress = 0, True
    while len(picks) < n and progress:
        progress = False
        for i, c in enumerate(classes):
            if len(picks) >= n:
                break
            order = ("bad", "good") if (i + rnd) % 2 == 0 else ("good", "bad")
            for lab in order:
                pool = pools.get((c, lab))
                if want[lab] > 0 and pool:
                    picks.append(pool.pop(rng.randrange(len(pool))))
                    want[lab] -= 1
                    progress = True
                    break
        rnd += 1
    if len(picks) != n:
        raise ValueError(f"only {len(picks)} of {n} functions available in flows {FLOWS}")
    rng.shuffle(picks)
    return [{"sha256": p["sha256"], "addr": p["addr"]} for p in picks], picks


def write_sample(run_dir: Path, sample: list[dict], key: list[dict], *, seed: int) -> Path:
    run_dir = Path(run_dir)
    (run_dir / "eval").mkdir(parents=True, exist_ok=True)
    out = run_dir / "sample.json"
    out.write_text(json.dumps({"functions": sample}, indent=1) + "\n", encoding="utf-8")
    (run_dir / "eval" / "sample_key.json").write_text(
        json.dumps({"seed": seed, "flows": list(FLOWS), "functions": key}, indent=1) + "\n",
        encoding="utf-8")
    return out


def agreement(run_dir: Path) -> dict[str, Any]:
    """Join summaries to the answer key by (sha256, addr) and print a per-function table.
    This is a rough Phase 5 read, not a metric: scoring rules are D-008 (Phase 7)."""
    run_dir = Path(run_dir)
    key = json.loads((run_dir / "eval" / "sample_key.json").read_text(encoding="utf-8"))["functions"]
    rows, cells = [], Counter()
    for k in sorted(key, key=lambda r: (int(r["cwe"].split("-")[-1]), r["label"], r["case_id"])):
        p = summary_path(run_dir, k["sha256"], k["addr"])
        s = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
        v = s["record"]["summary"]["verdict"] if s and s["record"] else None
        if v is None:
            cell = "no_summary"
        elif k["label"] == "bad":
            cell = "TP" if v["vulnerable"] else "FN"
        else:
            cell = "FP" if v["vulnerable"] else "TN"
        cells[cell] += 1
        rows.append({**k, "stem": stem(k["sha256"], k["addr"]), "cell": cell, "verdict": v})
    print(f"\n{'cwe':<8}{'label':<6}{'case':<9}{'addr':<8}{'cell':<5}verdict")
    for r in rows:
        v = r["verdict"]
        desc = ("(no summary)" if v is None else
                f"{v['mechanism']} {v['region']}/{v['access']}/{v['direction']} ({v['confidence']:.2f})")
        print(f"{r['cwe']:<8}{r['label']:<6}{r['case_id']:<9}{r['addr']:<8}{r['cell']:<5}{desc}")
        if v is not None:
            print(f"{'':<36}{v['reason'][:110]}")
    n = len(rows)
    agree = cells["TP"] + cells["TN"]
    print(f"\nagreement (rough, Phase 5): {agree}/{n}  TP {cells['TP']}  FN {cells['FN']}  "
          f"FP {cells['FP']}  TN {cells['TN']}  no summary {cells['no_summary']}")
    doc = {"functions": n, "cells": dict(cells), "rows": rows}
    (run_dir / "eval" / "agreement.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return doc