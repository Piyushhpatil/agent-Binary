"""Label join (Phase 3): attach ground-truth labels to program.json functions by address.

Invariant I4 -- the address is the only join key. program.json `addr` is already
image-base-relative (D-016), so it must equal manifest `addr_hex` exactly. This module
never adds or subtracts a base. The +/- image_base probe exists only to DETECT a
regression of that normalization; any hit is reported as `base_offset` and fails the run.

Invariant I1 -- this module reads ground truth. It is evaluation-side. Nothing under
taintwalk.analysis or taintwalk.llm may import it (tests/test_isolation.py, Phase 3).

Scope (D-015, I5) -- io.c support code is in_scope in program.json because the extractor
cannot tell it apart without labels. It is excluded HERE: every joined function carries
`scored`, and support/harness functions get scored=False with an exclude_reason.

The program is matched to its manifest entry by the stripped binary's sha256, never by
filename, so a mis-named file cannot silently join to the wrong labels.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from taintwalk.config import REPO_ROOT
from taintwalk.extract.report import load_manifest
from taintwalk.extract.schema import Program

SCORED_LABELS = {"bad", "good"}
TESTCASE_LABELS = {"bad", "good", "harness"}
MIN_JOIN_COVERAGE = 0.95  # PHASES.md Phase 3 Definition of Done


class JoinError(RuntimeError):
    """The program cannot be joined at all (structural problem, not a miss)."""


def _i(h: str) -> int:
    return int(h, 16)


def _hex(a: int) -> str:
    return hex(a)


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def entries_by_stripped_sha(manifest: dict) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for e in manifest["entries"]:
        sha = e["stripped_sha256"]
        if sha in idx:
            raise JoinError(f"duplicate stripped_sha256 {sha[:12]} in manifest "
                            f"({idx[sha]['case_id']}, {e['case_id']})")
        idx[sha] = e
    return idx


def load_program(path: Path) -> dict:
    """Schema-validate, then return the raw dict (field names = JSON keys)."""
    text = path.read_text(encoding="utf-8")
    Program.model_validate_json(text)
    return json.loads(text)


def _why_unlabeled(a: int, base: int, gt: dict[int, dict]) -> str:
    """An in-scope program function with no label at its exact address."""
    if (a + base) in gt or (a - base) in gt:
        return "base_offset"
    for g in gt.values():
        if g["size"] and g["addr"] < a < g["addr"] + g["size"]:
            return f"split:inside {g['addr_hex']}"
    return "unlabeled"


def _why_unrecovered(a: int, base: int, by_paddr: dict[int, dict]) -> str:
    """A test-case label with no in-scope program function at its address."""
    p = by_paddr.get(a)
    if p is not None:
        return f"excluded_by_extractor:{p.get('excluded_reason')}"
    if (a + base) in by_paddr or (a - base) in by_paddr:
        return "base_offset"
    for pa, pf in by_paddr.items():
        if pf.get("size") and pa < a < pa + pf["size"]:
            return f"merged:into {_hex(pa)}"
    return "not_recovered"


def join_program(prog: dict, entry: dict) -> dict:
    base = _i(prog["binary"]["image_base"])

    gt: dict[int, dict] = {}
    for f in entry["functions"]:
        if _i(f["addr_hex"]) != f["addr"]:
            raise JoinError(f"{entry['case_id']}: manifest addr/addr_hex disagree for {f['name']}")
        gt[f["addr"]] = f

    by_paddr = {_i(f["addr"]): f for f in prog["functions"]}
    in_scope = {a: f for a, f in by_paddr.items() if f["in_scope"]}

    joined: list[dict] = []
    unmatched_in_scope: list[dict] = []
    for a in sorted(in_scope):
        pf = in_scope[a]
        g = gt.get(a)
        if g is None:
            unmatched_in_scope.append({"addr": _hex(a), "reason": _why_unlabeled(a, base, gt)})
            continue
        label = g["label"]
        if label == "crt":
            reason = "crt_in_scope"          # structural CRT rule disagrees with DWARF
        elif label in SCORED_LABELS:
            reason = None
        else:
            reason = label                   # "support" or "harness"
        joined.append({
            "addr": _hex(a),
            "name": g["name"],
            "label": label,
            "role": g["role"],
            "cu": g["cu"],
            "scored": reason is None,
            "exclude_reason": reason,
            "size": g["size"],
            "size_agrees": g["size"] == pf.get("size"),
        })

    unrecovered: list[dict] = []
    for a in sorted(gt):
        g = gt[a]
        if g["label"] not in TESTCASE_LABELS or a in in_scope:
            continue
        unrecovered.append({"addr": g["addr_hex"], "name": g["name"], "label": g["label"],
                            "reason": _why_unrecovered(a, base, by_paddr)})

    present_tc = sum(1 for g in gt.values() if g["label"] in TESTCASE_LABELS)
    matched_tc = sum(1 for r in joined if r["label"] in TESTCASE_LABELS)
    reasons = [u["reason"] for u in unmatched_in_scope] + [u["reason"] for u in unrecovered]

    return {
        "case_id": entry["case_id"],
        "cwe": entry["cwe"],
        "flow_variant": entry["flow_variant"],
        "program_sha256": prog["binary"]["sha256"],
        "stats": {
            "present_testcase": present_tc,
            "matched_testcase": matched_tc,
            "scored_bad": sum(1 for r in joined if r["scored"] and r["label"] == "bad"),
            "scored_good": sum(1 for r in joined if r["scored"] and r["label"] == "good"),
            "excluded_support": sum(1 for r in joined if r["exclude_reason"] == "support"),
            "excluded_harness": sum(1 for r in joined if r["exclude_reason"] == "harness"),
            "crt_in_scope": sum(1 for r in joined if r["exclude_reason"] == "crt_in_scope"),
            "unmatched_in_scope": len(unmatched_in_scope),
            "unrecovered_testcase": len(unrecovered),
            "base_offset": sum(1 for r in reasons if r == "base_offset"),
            "size_mismatch": sum(1 for r in joined if not r["size_agrees"]),
        },
        "functions": joined,
        "unmatched_in_scope": unmatched_in_scope,
        "unrecovered": unrecovered,
    }


def _discover(run_dir: Path) -> list[tuple[Path, Path]]:
    single = run_dir / "program.json"
    if single.is_file():
        return [(single, run_dir / "labels.json")]
    progs = run_dir / "programs"
    if progs.is_dir():
        return [(p, run_dir / "labels" / p.name) for p in sorted(progs.glob("*.json"))]
    return []


def run_label(run_dir: Path, report: bool = False, manifest_path: Path | None = None) -> int:
    pairs = _discover(run_dir)
    if not pairs:
        print(f"no program.json or programs/*.json under {_rel(run_dir)}", file=sys.stderr)
        return 2

    manifest = load_manifest(manifest_path)
    idx = entries_by_stripped_sha(manifest)

    results: list[dict] = []
    schema_violations: list[str] = []
    no_entry: list[str] = []
    name_mismatch: list[str] = []
    join_errors: list[str] = []

    for prog_path, out_path in pairs:
        try:
            prog = load_program(prog_path)
        except ValidationError as exc:
            schema_violations.append(f"{prog_path.name}: {exc.error_count()} error(s)")
            continue
        entry = idx.get(prog["binary"]["sha256"])
        if entry is None:
            no_entry.append(prog_path.name)
            continue
        if prog_path.parent.name == "programs" and prog_path.stem != entry["case_id"]:
            name_mismatch.append(f"{prog_path.name} is really {entry['case_id']}")
            continue
        try:
            res = join_program(prog, entry)
        except JoinError as exc:
            join_errors.append(str(exc))
            continue
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        results.append(res)

    tot = {k: sum(r["stats"][k] for r in results) for k in (
        "present_testcase", "matched_testcase", "scored_bad", "scored_good",
        "excluded_support", "excluded_harness", "crt_in_scope", "unmatched_in_scope",
        "unrecovered_testcase", "base_offset", "size_mismatch")}
    cov = tot["matched_testcase"] / tot["present_testcase"] if tot["present_testcase"] else 0.0

    if report:
        print(f"{'case':<9} {'cwe':<8} {'fl':<3} {'tc':>7} {'bad':>4} {'good':>5} "
              f"{'supp':>5} {'harn':>5} {'unm':>4}")
        print("-" * 60)
        for r in results:
            s = r["stats"]
            print(f"{r['case_id']:<9} {r['cwe']:<8} {r['flow_variant']:<3} "
                  f"{s['matched_testcase']:>3}/{s['present_testcase']:<3} "
                  f"{s['scored_bad']:>4} {s['scored_good']:>5} {s['excluded_support']:>5} "
                  f"{s['excluded_harness']:>5} "
                  f"{s['unmatched_in_scope'] + s['unrecovered_testcase']:>4}")
        print()

    print(f"programs joined           : {len(results)}/{len(pairs)}")
    print(f"join coverage (test-case) : {tot['matched_testcase']}/{tot['present_testcase']} "
          f"= {cov:.1%}   [gated, min {MIN_JOIN_COVERAGE:.0%}]")
    print(f"scored functions          : {tot['scored_bad'] + tot['scored_good']}  "
          f"(bad {tot['scored_bad']}, good {tot['scored_good']})")
    print(f"excluded (eval-side scope): support {tot['excluded_support']}, "
          f"harness {tot['excluded_harness']}")
    print(f"unmatched in scope        : {tot['unmatched_in_scope']}")
    print(f"unrecovered test-case     : {tot['unrecovered_testcase']}")
    print(f"base_offset               : {tot['base_offset']}   [must be 0: D-016 normalization]")
    print(f"crt in scope              : {tot['crt_in_scope']}")
    print(f"size mismatches           : {tot['size_mismatch']}")
    print(f"schema violations         : {len(schema_violations)}"
          + ("  " + "; ".join(schema_violations) if schema_violations else ""))
    print(f"no manifest entry         : {len(no_entry)}" + (f"  {no_entry}" if no_entry else ""))
    if name_mismatch:
        print(f"filename/sha mismatch     : {name_mismatch}")
    if join_errors:
        print(f"join errors               : {join_errors}")

    for r in results:
        for u in r["unmatched_in_scope"]:
            print(f"  {r['case_id']}: in-scope {u['addr']} unlabeled -> {u['reason']}")
        for u in r["unrecovered"]:
            print(f"  {r['case_id']}: {u['label']} {u['addr']} not joined -> {u['reason']}")

    if report:
        rp = run_dir / "label_report.json"
        rp.write_text(json.dumps({
            "coverage_testcase": cov,
            "totals": tot,
            "schema_violations": schema_violations,
            "no_entry": no_entry,
            "name_mismatch": name_mismatch,
            "join_errors": join_errors,
            "cases": [{"case_id": r["case_id"], **r["stats"]} for r in results],
        }, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {_rel(rp)}")

    ok = (
        bool(results)
        and cov >= MIN_JOIN_COVERAGE
        and tot["base_offset"] == 0
        and tot["crt_in_scope"] == 0
        and not schema_violations
        and not no_entry
        and not name_mismatch
        and not join_errors
    )
    print("LABEL OK" if ok else "LABEL FAIL")
    return 0 if ok else 1