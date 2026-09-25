"""Phase 2 recovery report: join program.json to the manifest and measure.

Recovery rate = recovered user functions / ground-truth user functions, matched by
address (Invariant I4). Two denominators are reported because they answer different
questions:

  test-case  bad + good + harness -- the functions Phase 7 will actually score.
             This is the gated number.
  all-user   the above plus Juliet support code (io.c). Wider, and easier, since
             io.c functions are tiny printf wrappers.

CRT agreement compares the structural CRT rule (D-015 A, which never reads a label)
against the manifest's crt label. Disagreement means the rule is wrong, which would
silently change what gets analysed.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from pydantic import ValidationError

from taintwalk.config import REPO_ROOT, load_config
from taintwalk.extract.ghidra_runner import extract_cfg
from taintwalk.extract.schema import Program

TESTCASE_LABELS = {"bad", "good", "harness"}
USER_LABELS = TESTCASE_LABELS | {"support"}


def load_manifest(path: Path | None = None) -> dict:
    cfg = load_config()
    p = path or (REPO_ROOT / cfg["corpus"]["manifest"])
    return json.loads(p.read_text(encoding="utf-8"))


def sample_case_ids(manifest: dict, n: int | None) -> list[str]:
    ids = sorted(e["case_id"] for e in manifest["entries"])
    if n is None or n >= len(ids):
        return ids
    rng = random.Random(load_config()["corpus"]["seed"])
    return sorted(rng.sample(ids, n))


def _case_row(entry: dict, prog: Program) -> dict:
    gt = entry["functions"]
    gt_testcase = {f["addr_hex"] for f in gt if f["label"] in TESTCASE_LABELS}
    gt_user = {f["addr_hex"] for f in gt if f["label"] in USER_LABELS}
    gt_crt = {f["addr_hex"] for f in gt if f["label"] == "crt"}
    gt_size = {f["addr_hex"]: f["size"] for f in gt}

    in_scope = prog.in_scope_addrs()
    detected_crt = prog.excluded_addrs("crt")

    matched = gt_user & in_scope
    size_mismatch = sorted(
        a for a in matched
        if gt_size.get(a) is not None
        and gt_size[a] != next(f.size for f in prog.functions if f.addr == a)
    )

    return {
        "case_id": entry["case_id"],
        "cwe": entry["cwe"],
        "flow": entry["flow_variant"],
        "gt_testcase": len(gt_testcase),
        "rec_testcase": len(gt_testcase & in_scope),
        "gt_user": len(gt_user),
        "rec_user": len(gt_user & in_scope),
        "missing_testcase": sorted(gt_testcase - in_scope, key=lambda x: int(x, 16)),
        "extra_in_scope": sorted(in_scope - gt_user, key=lambda x: int(x, 16)),
        "crt_match": detected_crt == gt_crt,
        "crt_detected": len(detected_crt),
        "crt_expected": len(gt_crt),
        "decompile_failed": prog.counts["decompile_failed"],
        "indirect_in_scope": prog.counts["indirect_call_sites_in_scope"],
        "size_mismatch": size_mismatch,
        "total_functions": prog.counts["total"],
    }


def report(out_dir: Path, case_ids: list[str], manifest: dict) -> int:
    ecfg = extract_cfg()
    by_id = {e["case_id"]: e for e in manifest["entries"]}
    programs = out_dir / "programs"

    rows: list[dict] = []
    schema_violations: list[str] = []
    missing_files: list[str] = []

    for cid in case_ids:
        path = programs / f"{cid}.json"
        if not path.is_file():
            missing_files.append(cid)
            continue
        try:
            prog = Program.model_validate_json(path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            schema_violations.append(f"{cid}: {exc.error_count()} error(s)")
            continue
        rows.append(_case_row(by_id[cid], prog))

    print(f"{'case':<9} {'cwe':<8} {'fl':<3} {'tc':>6} {'user':>8} {'crt':>5} "
          f"{'dcf':>4} {'ind':>4} {'extra':>6}")
    print("-" * 64)
    for r in rows:
        tc = f"{r['rec_testcase']}/{r['gt_testcase']}"
        us = f"{r['rec_user']}/{r['gt_user']}"
        crt = "ok" if r["crt_match"] else f"{r['crt_detected']}!={r['crt_expected']}"
        print(f"{r['case_id']:<9} {r['cwe']:<8} {r['flow']:<3} {tc:>6} {us:>8} {crt:>5} "
              f"{r['decompile_failed']:>4} {r['indirect_in_scope']:>4} "
              f"{len(r['extra_in_scope']):>6}")

    gt_tc = sum(r["gt_testcase"] for r in rows)
    rec_tc = sum(r["rec_testcase"] for r in rows)
    gt_us = sum(r["gt_user"] for r in rows)
    rec_us = sum(r["rec_user"] for r in rows)
    rate_tc = rec_tc / gt_tc if gt_tc else 0.0
    rate_us = rec_us / gt_us if gt_us else 0.0
    crt_bad = [r["case_id"] for r in rows if not r["crt_match"]]
    size_bad = [r["case_id"] for r in rows if r["size_mismatch"]]
    dcf = sum(r["decompile_failed"] for r in rows)

    print()
    print(f"binaries reported        : {len(rows)}")
    print(f"recovery (test-case)     : {rec_tc}/{gt_tc} = {rate_tc:.1%}   [gated, min {ecfg['min_recovery']:.0%}]")
    print(f"recovery (all user code) : {rec_us}/{gt_us} = {rate_us:.1%}")
    print(f"CRT rule agreement       : {len(rows) - len(crt_bad)}/{len(rows)}"
          + (f"  mismatched: {crt_bad}" if crt_bad else ""))
    print(f"size agreement           : {len(rows) - len(size_bad)}/{len(rows)}"
          + (f"  mismatched: {size_bad}" if size_bad else ""))
    print(f"decompile failures       : {dcf}")
    print(f"schema violations        : {len(schema_violations)}"
          + ("  " + "; ".join(schema_violations) if schema_violations else ""))
    if missing_files:
        print(f"missing program.json     : {missing_files}")

    for r in rows:
        if r["missing_testcase"]:
            print(f"  {r['case_id']}: unrecovered test-case functions {r['missing_testcase']}")
        if r["extra_in_scope"]:
            print(f"  {r['case_id']}: in-scope but unlabeled {r['extra_in_scope']}")

    payload = {
        "cases": rows,
        "summary": {
            "binaries": len(rows),
            "recovery_testcase": rate_tc,
            "recovery_all_user": rate_us,
            "crt_mismatches": crt_bad,
            "size_mismatches": size_bad,
            "decompile_failures": dcf,
            "schema_violations": schema_violations,
            "missing_files": missing_files,
        },
    }
    out_path = out_dir / "extract_report.json"
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out_path.relative_to(REPO_ROOT)}")

    ok = (
        rate_tc >= ecfg["min_recovery"]
        and not schema_violations
        and not missing_files
        and not crt_bad
    )
    print("REPORT OK" if ok else "REPORT FAIL")
    return 0 if ok else 1