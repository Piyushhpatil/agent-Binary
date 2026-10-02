"""`taintwalk selftest --leak` -- prove the leak gate on every real prompt input.

Scans EVERY in-scope function of every program.json (not a sample), as the text a
prompt would carry: pseudo-C plus external import names. For each function it records
  raw     the gate on unredacted input (shows what redaction is protecting against)
  final   the gate on redacted input (must be clean)
and it plants one canary per layer to prove the gate is live, not vacuously passing.

Phase 6 (D-026) adds:
  full    every complete base prompt (SYSTEM + user, exactly as build_prompt makes it),
          gated with both layers: the text a walk leaf or Baseline B sends
  callee  every persisted real summary (runs/**/summaries/*.json) rendered as a callee
          block and gated with its own binary's name layer. In the walk, model output
          re-enters prompts; checking real model text here turns a mid-walk abort into
          an offline finding
  and a third canary, planted in a rendered model field.

Evaluation-side: it reads the manifest to bucket results by label.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from taintwalk.analysis.prompts import CalleeView, build_prompt, render_callee_context
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


def _canary_summary(planted: str) -> dict:
    """A valid TaintSummary whose guard_expr carries a planted leak."""
    return {
        "params": [{"index": 0, "inferred_type": "char *", "role": "buffer"}],
        "sources": [],
        "sinks": [{"sink_kind": "call_arg", "callee": "strcpy", "evidence_line": 1, "tainted_args": [0],
                   "guarded": True, "guard_expr": planted, "confidence": 0.5}],
        "propagation": [{"src": "param:0", "dst": "sink:0", "sanitized": True}],
        "returns_taint": False,
        "callee_effects": [],
        "verdict": {"reason": "r", "mechanism": "none", "region": "not_applicable",
                    "access": "not_applicable", "direction": "not_applicable",
                    "vulnerable": False, "confidence": 0.5},
    }


def _real_summaries(runs_dir: Path, problems: list[str]) -> tuple[int, dict[tuple[str, str], str]]:
    """Every persisted summary row under runs/**/summaries/, deduplicated by (binary, summary).
    Returns (rows read, {(sha256, canonical summary json): function name})."""
    rows = 0
    unique: dict[tuple[str, str], str] = {}
    for rp in sorted(runs_dir.rglob("*.json")):
        if rp.parent.name != "summaries":
            continue
        try:
            row = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"{rp}: unreadable ({exc})")
            continue
        if not isinstance(row, dict) or not {"binary_sha256", "record"} <= set(row):
            problems.append(f"{rp}: not a summary row")
            continue
        rows += 1
        rec = row["record"]
        if rec is None:
            continue
        key = (row["binary_sha256"], json.dumps(rec["summary"], sort_keys=True))
        unique.setdefault(key, rec["function"])
    return rows, unique


def run_leak_selftest(programs_dir: Path, manifest_path: Path | None = None) -> int:
    t0 = time.monotonic()
    mp = manifest_path or (REPO_ROOT / load_config()["corpus"]["manifest"])
    cap = load_config()["walk"]["callee_context_max_chars"]
    files = sorted(programs_dir.glob("*.json"))
    if not files:
        print(f"no program.json files in {programs_dir}")
        print("LEAK SELFTEST FAIL")
        return 2
    idx = {e["stripped_sha256"]: e
           for e in json.loads(Path(mp).read_text(encoding="utf-8"))["entries"]}

    n_inputs = 0
    n_full = 0
    raw_leak: Counter = Counter()
    red_funcs: Counter = Counter()
    red_lits = 0
    leaks: list[str] = []
    full_leaks: list[str] = []
    callee_leaks: list[str] = []
    problems: list[str] = []
    canary_static: bool | None = None
    canary_name: bool | None = None
    canary_render: bool | None = None

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
                if pc.strip():
                    n_full += 1
                    try:
                        p = build_prompt(f["ghidra_name"], pc, binary_sha256=None)   # static gate inside
                        assert_clean(p.system + "\n" + p.user, sha, manifest_path=mp)
                    except LeakError as exc:
                        full_leaks.append(f"{fp.stem} {f['addr']} [{label}] full prompt\n{exc}")
            if canary_name is None:
                canary_static = _caught('FUN_1("Calling bad()...");', sha, mp, "static")
                support = next((g["name"] for g in entry["functions"]
                                if g["label"] == "support"), None)
                canary_name = support is not None and _caught(
                    f"FUN_1(); /* {support} */", sha, mp, "name")
                if support is not None:
                    ctx = render_callee_context(
                        ("  FUN_00100001(1);",),
                        [CalleeView("0x1", "FUN_00100001", "ok", summary=_canary_summary(support))],
                        max_chars=cap)
                    canary_render = support in ctx.text and _caught(ctx.text, sha, mp, "name")
                else:
                    canary_render = False
        except LeakCheckConfigError as exc:
            problems.append(f"{fp.name}: {exc}")

    n_rows, unique = _real_summaries(REPO_ROOT / "runs", problems)
    if not unique:
        problems.append("no persisted summaries under runs/**/summaries/ (expected the Phase 5 runs)")
    for (sha, s_json), name in sorted(unique.items()):
        try:
            ctx = render_callee_context((f"  {name}(1);",),
                                        [CalleeView("0x1", name, "ok", summary=json.loads(s_json))],
                                        max_chars=cap)
            assert_clean(ctx.text, sha, manifest_path=manifest_path)   # None: Juliet + real-code manifests (Phase 9)
        except LeakError as exc:
            callee_leaks.append(f"{sha[:12]} {name} rendered summary\n{exc}")
        except (LeakCheckConfigError, ValidationError, ValueError) as exc:
            problems.append(f"{sha[:12]} {name}: {type(exc).__name__}: {exc}")

    red_scored = sum(n for l, n in red_funcs.items() if l in SCORED)

    print(f"programs                  : {len(files)}")
    print(f"prompt inputs scanned     : {n_inputs} (every in-scope function)")
    print(f"raw leaks, no redaction   : {sum(raw_leak.values())}  {dict(sorted(raw_leak.items()))}")
    print(f"redacted literals         : {red_lits} in {sum(red_funcs.values())} functions  "
          f"{dict(sorted(red_funcs.items()))}")
    print(f"redactions in scored fns  : {red_scored}   [must be 0]")
    print(f"leaks after redaction     : {len(leaks)}   [must be 0]")
    print(f"full prompts gated        : {n_full} (SYSTEM + user, both layers)")
    print(f"full-prompt leaks         : {len(full_leaks)}   [must be 0]")
    print(f"real summaries rendered   : {len(unique)} unique from {n_rows} rows, gated as callee blocks")
    print(f"callee-block leaks        : {len(callee_leaks)}   [must be 0]")
    print(f"canary, static layer      : {'CAUGHT' if canary_static else 'MISSED'}")
    print(f"canary, name layer        : {'CAUGHT' if canary_name else 'MISSED'}")
    print(f"canary, rendered field    : {'CAUGHT' if canary_render else 'MISSED'}")
    print(f"elapsed                   : {time.monotonic() - t0:.1f} s")
    if problems:
        print(f"problems                  : {problems[:10]}")
    for block in (leaks + full_leaks + callee_leaks)[:5]:
        print(block)
    extra = len(leaks) + len(full_leaks) + len(callee_leaks) - 5
    if extra > 0:
        print(f"... {extra} more leaking items")

    ok = (n_inputs > 0 and not problems and not leaks and not full_leaks and not callee_leaks
          and red_scored == 0 and bool(canary_static) and bool(canary_name) and bool(canary_render))
    print(f"OK: 0 leaks across {n_inputs} prompt inputs, {n_full} full prompts, "
          f"{len(unique)} callee blocks" if ok else "LEAK SELFTEST FAIL")
    return 0 if ok else 1