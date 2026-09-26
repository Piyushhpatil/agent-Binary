"""`taintwalk selftest --leak` -- prove the leak gate on every real prompt input.

Scans EVERY in-scope function of every program.json (not a sample), as the text a
prompt would carry: pseudo-C plus external import names. For each function it records
  raw     the gate on unredacted input (shows what redaction is protecting against)
  final   the gate on redacted input (must be clean)
and it plants one canary per layer to prove the gate is live, not vacuously passing.

Evaluation-side: it reads the manifest to bucket results by label.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from taintwalk.analysis.sanitize import redact_leaky_literals
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.eval.join import load_program
from taintwalk.util.leakcheck import LeakCheckConfigError, LeakError, assert_clean

SCORED = {"bad", "good"}


def _prompt_input(pseudo_c: str, callees: list[dict]) -> str:
    imports = sorted({c["name"] for c in callees if c["kind"] == "external" and c["name"]})
    return pseudo_c + "\n/* imports: " + ", ".join(imports) + " */\n"


def _caught(text: str, sha: str, mp: Path, layer: str) -> bool:
    try:
        assert_clean(text, sha, manifest_path=mp)
    except LeakError as exc:
        return any(f.layer == layer for f in exc.findings)
    return False


def run_leak_selftest(programs_dir: Path, manifest_path: Path | None = None) -> int:
    mp = manifest_path or (REPO_ROOT / load_config()["corpus"]["manifest"])
    files = sorted(programs_dir.glob("*.json"))
    if not files:
        print(f"no program.json files in {programs_dir}")
        print("LEAK SELFTEST FAIL")
        return 2
    idx = {e["stripped_sha256"]: e
           for e in json.loads(Path(mp).read_text(encoding="utf-8"))["entries"]}

    n_inputs = 0
    raw_leak: Counter = Counter()
    red_funcs: Counter = Counter()
    red_lits = 0
    leaks: list[str] = []
    problems: list[str] = []
    canary_static: bool | None = None
    canary_name: bool | None = None

    for fp in files:
        try:
            prog = load_program(fp)
        except ValidationError as exc:
            problems.append(f"{fp.name}: schema, {exc.error_count()} error(s)")
            continue
        sha = prog["binary"]["sha256"]
        entry = idx.get(sha)
        if entry is None:
            problems.append(f"{fp.name}: no manifest entry for its sha256")
            continue
        gt = {g["addr_hex"]: g["label"] for g in entry["functions"]}
        try:
            for f in prog["functions"]:
                if not f["in_scope"]:
                    continue
                label = gt.get(f["addr"], "UNLABELED")
                pc = f["pseudo_c"] or ""
                n_inputs += 1
                try:
                    assert_clean(_prompt_input(pc, f["callees"]), sha, manifest_path=mp)
                except LeakError:
                    raw_leak[label] += 1
                red, k = redact_leaky_literals(pc)
                if k:
                    red_funcs[label] += 1
                    red_lits += k
                try:
                    assert_clean(_prompt_input(red, f["callees"]), sha, manifest_path=mp)
                except LeakError as exc:
                    leaks.append(f"{fp.stem} {f['addr']} [{label}]\n{exc}")
            if canary_name is None:
                canary_static = _caught('FUN_1("Calling bad()...");', sha, mp, "static")
                support = next((g["name"] for g in entry["functions"]
                                if g["label"] == "support"), None)
                canary_name = support is not None and _caught(
                    f"FUN_1(); /* {support} */", sha, mp, "name")
        except LeakCheckConfigError as exc:
            problems.append(f"{fp.name}: {exc}")

    red_scored = sum(n for l, n in red_funcs.items() if l in SCORED)

    print(f"programs                  : {len(files)}")
    print(f"prompt inputs scanned     : {n_inputs} (every in-scope function)")
    print(f"raw leaks, no redaction   : {sum(raw_leak.values())}  {dict(sorted(raw_leak.items()))}")
    print(f"redacted literals         : {red_lits} in {sum(red_funcs.values())} functions  "
          f"{dict(sorted(red_funcs.items()))}")
    print(f"redactions in scored fns  : {red_scored}   [must be 0]")
    print(f"leaks after redaction     : {len(leaks)}   [must be 0]")
    print(f"canary, static layer      : {'CAUGHT' if canary_static else 'MISSED'}")
    print(f"canary, name layer        : {'CAUGHT' if canary_name else 'MISSED'}")
    if problems:
        print(f"problems                  : {problems}")
    for block in leaks[:5]:
        print(block)
    if len(leaks) > 5:
        print(f"... {len(leaks) - 5} more leaking functions")

    ok = (n_inputs > 0 and not problems and not leaks and red_scored == 0
          and bool(canary_static) and bool(canary_name))
    print(f"OK: 0 leaks across {n_inputs} prompt inputs" if ok else "LEAK SELFTEST FAIL")
    return 0 if ok else 1