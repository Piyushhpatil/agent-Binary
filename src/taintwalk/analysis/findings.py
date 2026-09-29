"""Label-free findings from a finished walk (Phase 7, D-008).

One row per walked function: its factored verdict, its unguarded sinks, whether the verdict is
conditional on its own parameters (D-026), and a trail through the callees its verdict can rest
on. Nothing here knows a label or a CWE id; the eval side maps verdicts to classes
(eval/cwe_map.py) and scores them (D-008, D-021). The inputs are the persisted walk outputs only
(walk.json and summaries.json), so building findings never calls a model.

A walked function whose analysis failed (for example max_tokens) gets a row with status
"no_summary" and every verdict field null. It is never turned into "not vulnerable".
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from taintwalk.analysis.callgraph import addr_key
from taintwalk.analysis.summary_schema import SummaryRecord

FINDINGS_VERSION = 1
MAX_TRAIL_DEPTH = 8          # the longest in-scope chain in the corpus is 8 functions (D-026 survey)
VERDICT_FIELDS = ("vulnerable", "mechanism", "region", "access", "direction", "confidence")


class FindingsError(ValueError):
    """The walk outputs are missing or disagree with each other; nothing is built from them."""


def _read(path: Path) -> Any:
    if not path.exists():
        raise FindingsError(f"{path} is missing; is this a finished walk run dir?")
    return json.loads(path.read_text(encoding="utf-8"))


def _unguarded_sinks(summary: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"index": i, "sink_kind": s["sink_kind"], "callee": s["callee"],
             "evidence_line": s["evidence_line"]}
            for i, s in enumerate(summary["sinks"]) if not s["guarded"]]


def _conditional(summary: dict[str, Any]) -> bool:
    """True when a parameter reaches a sink unsanitized: whether the flaw is real then depends on
    what the caller passes, which this function's own summary cannot settle (D-026)."""
    return any(e["src"].startswith("param:") and e["dst"].startswith("sink:") and not e["sanitized"]
               for e in summary["propagation"])


def _trail(addr: str, fns: dict[str, dict], records: dict[str, dict]) -> list[dict[str, Any]]:
    """Breadth-first through the walked callees, in address order, up to MAX_TRAIL_DEPTH hops.
    Every callee is traversed, so a forwarder with no sink of its own does not cut the trail.
    A callee is listed when its summary is vulnerable or has an unguarded sink. Each function
    appears once, at its shortest depth, so cycles and diamonds terminate."""
    out: list[dict[str, Any]] = []
    seen = {addr}
    frontier = [addr]
    for depth in range(1, MAX_TRAIL_DEPTH + 1):
        nxt: list[str] = []
        for a in frontier:
            for c in sorted(fns[a]["callees"], key=addr_key):
                if c in seen or c not in fns:
                    continue
                seen.add(c)
                nxt.append(c)
                rec = records.get(c)
                if rec is None:
                    continue
                s = rec["summary"]
                sinks = _unguarded_sinks(s)
                if s["verdict"]["vulnerable"] or sinks:
                    out.append({"address": c, "function": fns[c]["function"], "depth": depth,
                                "vulnerable": s["verdict"]["vulnerable"],
                                "mechanism": s["verdict"]["mechanism"],
                                "conditional": _conditional(s), "sinks": sinks})
        if not nxt:
            break
        frontier = nxt
    return out


def _no_summary_row(addr: str, f: dict[str, Any]) -> dict[str, Any]:
    return {"address": addr, "function": f["function"], "status": "no_summary",
            "failure": f["failure"] or f["status"], **{k: None for k in VERDICT_FIELDS},
            "conditional": None, "source_kinds": [], "sinks": [], "trail": []}


def build_findings(run_dir: Path) -> dict[str, Any]:
    """Findings for one walk run dir. Fails closed when walk.json and summaries.json disagree."""
    run_dir = Path(run_dir)
    walk = _read(run_dir / "walk.json")
    summaries = _read(run_dir / "summaries.json")
    fns: dict[str, dict] = walk["functions"]
    missing = sorted(set(fns) - set(summaries), key=addr_key)
    extra = sorted(set(summaries) - set(fns), key=addr_key)
    if missing or extra:
        raise FindingsError(f"{run_dir.name}: walked but no summaries.json entry {missing[:5]}; "
                            f"summaries.json entry but not walked {extra[:5]}")
    records: dict[str, dict] = {}
    for a in sorted(fns, key=addr_key):
        rec, status = summaries[a], fns[a]["status"]
        if (rec is None) != (status != "ok"):
            raise FindingsError(f"{run_dir.name} {a}: walk status {status!r} but the record is "
                                f"{'absent' if rec is None else 'present'}")
        if rec is None:
            continue
        SummaryRecord.model_validate(rec)
        if rec["address"] != a:
            raise FindingsError(f"{run_dir.name}: summaries.json key {a} holds the record of {rec['address']}")
        records[a] = rec
    rows: list[dict[str, Any]] = []
    for a in sorted(fns, key=addr_key):
        f, rec = fns[a], records.get(a)
        if rec is None:
            rows.append(_no_summary_row(a, f))
            continue
        s = rec["summary"]
        rows.append({"address": a, "function": f["function"], "status": "ok", "failure": None,
                     **{k: s["verdict"][k] for k in VERDICT_FIELDS},
                     "conditional": _conditional(s),
                     "source_kinds": sorted({x["kind"] for x in s["sources"]}),
                     "sinks": _unguarded_sinks(s),
                     "trail": _trail(a, fns, records)})
    return {"findings_version": FINDINGS_VERSION, "binary_sha256": walk["binary_sha256"],
            "prompt_version": walk["prompt_version"],
            "callee_context_version": walk["callee_context_version"],
            "provider": walk["provider"], "walked": len(rows),
            "no_summary": sum(r["status"] == "no_summary" for r in rows), "findings": rows}


def write_findings(run_dir: Path) -> Path:
    """Write run_dir/findings.json with sorted keys and no timestamps, so it is byte-deterministic."""
    doc = build_findings(run_dir)
    out = Path(run_dir) / "findings.json"
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return out