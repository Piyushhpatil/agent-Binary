"""Single-function taint analysis runner (Phase 5; D-019, D-021). Analysis side: label-free.

Input is a sample file holding ONLY (sha256, addr) pairs; load_sample() rejects any other
key, so a label cannot ride along by accident. For each pair:
    program.json -> build_prompt (redact, collapse, number, gate) -> provider.complete
    (gate, cache, send, validate, <=1 repair) -> SummaryRecord -> evidence checks
and writes, under the run dir (I2):
    system.txt                 the system prompt, once
    prompts/<stem>.json        the user prompt and every raw model reply
    summaries/<stem>.json      the record plus provenance (sorted keys, D-019)
    analysis_report.json       label-free counts; the DoD gate is schema_valid >= 0.95
A LeakError is never caught: a leaking prompt aborts the run loudly (D-017).
The Phase 6 walk (D-026) reuses analyze_function() with a callee context, a stem tag and
extra row fields; their defaults reproduce Phase 5 exactly.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from taintwalk.analysis.prompts import PROMPT_VERSION, SYSTEM, build_prompt
from taintwalk.analysis.summary_schema import (
    SCHEMA_VERSION,
    SummaryRecord,
    TaintSummary,
    evidence_issues,
)
from taintwalk.llm.base import ContextOverflow, LLMProvider

SAMPLE_KEYS = frozenset({"sha256", "addr"})
SCHEMA_VALID_MIN = 0.95


def stem(sha256: str, addr: str) -> str:
    return f"{sha256[:12]}_{addr}"


def summary_path(run_dir: Path, sha256: str, addr: str) -> Path:
    return Path(run_dir) / "summaries" / f"{stem(sha256, addr)}.json"


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def load_sample(path: Path) -> list[tuple[str, str]]:
    """Read a sample file: {"functions": [{"sha256": ..., "addr": ...}, ...]} and nothing else."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or set(doc) != {"functions"}:
        raise ValueError("sample file must hold exactly one key, 'functions'")
    out: list[tuple[str, str]] = []
    for it in doc["functions"]:
        if not isinstance(it, dict) or set(it) != SAMPLE_KEYS:
            raise ValueError(f"sample entry must carry exactly {sorted(SAMPLE_KEYS)}, got {sorted(it)}")
        out.append((it["sha256"], it["addr"]))
    if not out:
        raise ValueError("sample is empty")
    if len(set(out)) != len(out):
        raise ValueError("sample has duplicate (sha256, addr) pairs")
    return out


def load_programs(programs_dir: Path) -> dict[str, dict[str, Any]]:
    """Index every program.json in a directory by its stripped binary's sha256."""
    progs: dict[str, dict[str, Any]] = {}
    for p in sorted(Path(programs_dir).glob("*.json")):
        prog = json.loads(p.read_text(encoding="utf-8"))
        sha = prog["binary"]["sha256"]
        if sha in progs:
            raise ValueError(f"two programs share sha256 {sha[:12]}")
        progs[sha] = prog
    if not progs:
        raise ValueError(f"no program.json files in {programs_dir}")
    return progs


def analyze_function(
    provider: LLMProvider,
    prog: dict[str, Any],
    addr: str,
    run_dir: Path,
    *,
    retry_failed: bool = False,
    callee_context: str = "",
    tag: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One function -> one row. The defaults are Phase 5 exactly. The walk (D-026) passes
    callee_context (appended after the numbered code), tag (a stem suffix such as ".it1", so
    fixed-point iterations do not overwrite each other) and extra (fields merged into the row)."""
    sha = prog["binary"]["sha256"]
    fn = next((f for f in prog["functions"] if f["addr"] == addr), None)
    if fn is None or not fn["in_scope"] or fn.get("pseudo_c") is None:
        raise ValueError(f"{stem(sha, addr)}: not an in-scope function with pseudo-C")
    name = fn["ghidra_name"]
    prompt = build_prompt(name, fn["pseudo_c"], binary_sha256=sha,     # gate inside
                          callee_context=callee_context)

    t0 = time.monotonic()
    comp, overflow = None, ""
    try:
        comp = provider.complete(prompt.system, prompt.user, TaintSummary,
                                 binary_sha256=sha, retry_failed=retry_failed)
    except ContextOverflow as e:           # not cached, not repairable: record and go on
        overflow = str(e)
    wall = time.monotonic() - t0

    row: dict[str, Any] = {
        "binary_sha256": sha,
        "address": addr,
        "function": name,
        "prompt_version": PROMPT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "provider": provider.identity(),
        "lines": len(prompt.lines),
        "redactions": prompt.redactions,
        "collapsed": prompt.collapsed,
        "wall_s": round(wall, 2),
        "record": None,
        "evidence_issues": [],
    }
    if comp is None:
        row.update(status="failed", failure="context_overflow", error=overflow, repaired=False,
                   cache_hit=False, cache_key=None, attempts=0, usage=None, chars_per_token=[])
        attempts: list[dict[str, Any]] = []
    else:
        attempts = list(comp.attempts)
        row.update(
            status=comp.status, failure=comp.failure, repaired=comp.repaired, cache_hit=comp.cache_hit,
            cache_key=comp.key, attempts=len(attempts), usage=asdict(comp.usage),
            chars_per_token=[(a.get("detail") or {}).get("chars_per_token") for a in attempts],
        )
        if comp.ok:
            rec = SummaryRecord(schema_version=SCHEMA_VERSION, function=name, address=addr,
                                summary=TaintSummary.model_validate(comp.data))
            row["record"] = rec.model_dump(mode="json")
            row["evidence_issues"] = [list(x) for x in evidence_issues(rec.summary, list(prompt.lines), name)]
    if extra:
        row.update(extra)

    s = stem(sha, addr) + tag
    _write_json(Path(run_dir) / "prompts" / f"{s}.json", {
        "system_sha256": hashlib.sha256(prompt.system.encode()).hexdigest(),
        "user": prompt.user,
        "attempts": [{k: a.get(k) for k in ("text", "stop_reason", "error", "detail")} for a in attempts],
    })
    _write_json(Path(run_dir) / "summaries" / f"{s}.json", row)
    return row


def run_analyze(
    provider: LLMProvider,
    sample: list[tuple[str, str]],
    programs: dict[str, dict[str, Any]],
    run_dir: Path,
    *,
    retry_failed: bool = False,
) -> list[dict[str, Any]]:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "system.txt").write_text(SYSTEM, encoding="utf-8")
    missing = [stem(s, a) for s, a in sample if s not in programs]
    if missing:
        raise ValueError(f"no program.json for {missing[:3]}")
    rows = []
    for i, (sha, addr) in enumerate(sample, 1):
        row = analyze_function(provider, programs[sha], addr, run_dir, retry_failed=retry_failed)
        tag = "CACHE" if row["cache_hit"] else f"{row['wall_s']:.1f}s"
        extra = " repaired" if row["repaired"] else ""
        fail = f" {row['failure']}" if row["status"] != "ok" else ""
        print(f"[{i:>3}/{len(sample)}] {stem(sha, addr)}  {row['status']}{fail}{extra}  {tag}", flush=True)
        rows.append(row)
    return rows


def analysis_report(rows: list[dict[str, Any]], run_dir: Path) -> int:
    """Label-free report. Returns 0 when schema_valid >= SCHEMA_VALID_MIN, else 1."""
    n = len(rows)
    ok = sum(r["status"] == "ok" for r in rows)
    cpt = [c for r in rows for c in r["chars_per_token"] if isinstance(c, (int, float))]
    issues = Counter(kind for r in rows for _, kind in r["evidence_issues"])
    live = [r for r in rows if not r["cache_hit"] and r["usage"]]
    rep = {
        "functions": n,
        "schema_valid": ok,
        "schema_valid_rate": round(ok / n, 4) if n else 0.0,
        "repaired": sum(bool(r["repaired"]) for r in rows),
        "failures": dict(Counter(r["failure"] for r in rows if r["status"] != "ok")),
        "cache_hits": sum(bool(r["cache_hit"]) for r in rows),
        "prompts_gated": n + sum(bool(r["repaired"]) and not r["cache_hit"] for r in rows),
        "evidence_issues": dict(issues),
        "functions_with_evidence_issues": sum(bool(r["evidence_issues"]) for r in rows),
        "verdict_vulnerable": sum(bool(r["record"] and r["record"]["summary"]["verdict"]["vulnerable"])
                                  for r in rows),
        "mechanisms": dict(Counter(r["record"]["summary"]["verdict"]["mechanism"] for r in rows if r["record"])),
        "chars_per_token": ({"min": min(cpt), "mean": round(statistics.mean(cpt), 2), "max": max(cpt)}
                            if cpt else None),
        "tokens_in": sum(r["usage"]["input_tokens"] for r in live),
        "tokens_out": sum(r["usage"]["output_tokens"] for r in live),
        "model_wall_s": round(sum(r["wall_s"] for r in live), 1),
    }
    _write_json(Path(run_dir) / "analysis_report.json", rep)
    passed = n > 0 and rep["schema_valid_rate"] >= SCHEMA_VALID_MIN
    print(f"\nfunctions          : {n}")
    print(f"schema-valid       : {ok}/{n} = {100 * rep['schema_valid_rate']:.1f}%  "
          f"[gate >= {100 * SCHEMA_VALID_MIN:.0f}% after <= 1 repair]  repaired {rep['repaired']}")
    if rep["failures"]:
        print(f"failures           : {rep['failures']}")
    print(f"evidence issues    : {rep['functions_with_evidence_issues']} functions  {rep['evidence_issues']}")
    print(f"verdicts           : {rep['verdict_vulnerable']} vulnerable  {rep['mechanisms']}")
    print(f"chars/token        : {rep['chars_per_token']}")
    print(f"tokens (this run)  : in {rep['tokens_in']}  out {rep['tokens_out']}  "
          f"model time {rep['model_wall_s']} s  cache hits {rep['cache_hits']}")
    print(f"leak gate          : {rep['prompts_gated']} prompts gated before any I/O; 0 violations "
          f"(a violation aborts the run)")
    print(f"summaries          : {Path(run_dir) / 'summaries'}")
    print("ANALYZE OK" if passed else "ANALYZE FAIL: schema-valid rate below the gate")
    return 0 if passed else 1