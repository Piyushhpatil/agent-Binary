"""Per-function rows for all seven rungs (Phase 8, D-030; I6).

Every rung emits one row per walked function,
    {"outcome": "flagged" | "clear" | "abstain", "score": number | None, "verdict": {...} | None},
collected in one document per rung, keyed by the stripped binary's sha256 and the function address:
    {"rung", "kind", "score_scale", "definition", "identity", "programs": {sha: {addr: row}}}.

R1-R3 are computed here from program.json alone (no labels, no model):
  R1  flawfinder, per function: pseudo-C after the alias adapter, one file per function, default
      options; flagged on at least one hit; score = highest Level (0 when none).
  R2  input rule, per function: flagged when the function itself calls a member of INPUT_CALLS
      (after the alias adapter); no score.
  R3  reachability: flagged when any function reachable from it in the in-scope call graph (itself
      included) is R1-flagged; score = highest R1 level over that set.
R4-R7 are read from walk run dirs (llm_rung_doc): the walk arm from findings; the no-context arm from
the walk's baseline/ rows, falling back to the walk row only where the walk prompt had no callee
block (context_chars == 0: both prompts are the same bytes). Anything else fails closed.

The walked set is callgraph.plan_walk's, the functions the walk analyzes, so every rung answers for
exactly the same functions. Nothing here imports taintwalk.llm (scoring must not load it).
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

from taintwalk.analysis.callgraph import addr_key, build_graph, plan_walk
from taintwalk.analysis.findings import VERDICT_FIELDS, build_findings
from taintwalk.analysis.summary_schema import SummaryRecord
from taintwalk.eval.metrics import row_from_finding
from taintwalk.eval.score import discover_runs

FLAWFINDER_VERSION = "2.0.20"
ALIAS = re.compile(r"\b__isoc(99|23)_(\w+)")
INPUT_CALLS = frozenset({
    "read", "pread", "recv", "recvfrom", "recvmsg", "fread", "fgets", "fgetws", "fgetc", "fgetwc",
    "getc", "getwc", "getchar", "getwchar", "gets", "getline", "getdelim", "scanf", "wscanf",
    "fscanf", "fwscanf", "vscanf", "vfscanf", "getenv", "secure_getenv", "rand",
})
LLM_RUNGS = {"R4": ("baseline", "ollama"), "R5": ("walk", "ollama"),
             "R6": ("baseline", "anthropic"), "R7": ("walk", "anthropic")}
DEFINITIONS = {
    "R1": (f"flawfinder {FLAWFINDER_VERSION}, default options, on each walked function's pseudo-C after "
           "the alias adapter; flagged on at least one hit; score = highest Level (0 when none)"),
    "R2": "flagged when the function itself calls a member of the input list (after the alias adapter)",
    "R3": ("flagged when any function reachable from it in the in-scope call graph (itself included) "
           "is R1-flagged; score = highest R1 level over that set"),
    "R4": "no-context arm: walk prompt without its callee block (byte-identical to analyze-one), local model",
    "R5": "TaintWalk bottom-up walk, local model",
    "R6": "no-context arm: walk prompt without its callee block (byte-identical to analyze-one), cloud model",
    "R7": "TaintWalk bottom-up walk, headline cloud model",
}


class RungError(RuntimeError):
    """A rung's rows cannot be built exactly; nothing is scored from them."""


# ---- shared -----------------------------------------------------------------------------------

def unalias(text: str) -> str:
    """The D-030 alias adapter: glibc's versioned names (__isoc23_fscanf) back to the plain name."""
    return ALIAS.sub(r"\2", text)


def walked_functions(prog: dict[str, Any]) -> list[str]:
    """The walk's own function set (callgraph.plan_walk), in walk order."""
    return list(plan_walk(build_graph(prog)).functions)


def load_programs(programs_dir: Path) -> dict[str, dict[str, Any]]:
    """program file stem -> program.json. Fails closed on duplicate binaries or an empty dir."""
    progs: dict[str, dict[str, Any]] = {}
    seen: dict[str, str] = {}
    for p in sorted(Path(programs_dir).glob("*.json")):
        prog = json.loads(p.read_text(encoding="utf-8"))
        sha = prog["binary"]["sha256"]
        if sha in seen:
            raise RungError(f"{p.stem} and {seen[sha]} are the same binary {sha[:12]}")
        seen[sha] = p.stem
        progs[p.stem] = prog
    if not progs:
        raise RungError(f"no program.json files in {programs_dir}")
    return progs


def _row(flagged: bool, score: int | None) -> dict[str, Any]:
    return {"outcome": "flagged" if flagged else "clear", "score": score, "verdict": None}


def _reachable(succ: Mapping[str, tuple[str, ...]], start: str) -> set[str]:
    seen, stack = {start}, [start]
    while stack:
        for c in succ.get(stack.pop(), ()):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return seen


def write_doc(doc: dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


# ---- R1-R3 ----------------------------------------------------------------------------------

def flawfinder_exe() -> str:
    exe = shutil.which("flawfinder")
    if not exe:
        raise RungError(f"flawfinder is not on PATH; install flawfinder=={FLAWFINDER_VERSION} in the venv")
    return exe


def flawfinder_version(exe: str) -> str:
    return subprocess.run([exe, "--version"], capture_output=True, text=True, check=False).stdout.strip()


def flawfinder_levels(progs: dict[str, dict[str, Any]], work_dir: Path) -> dict[str, dict[str, int | None]]:
    """program stem -> walked addr -> highest flawfinder Level (None when no hit). One file per
    function (<stem>/<addr>.c), so every hit maps back to exactly one function; an unmapped hit fails."""
    exe = flawfinder_exe()
    version = flawfinder_version(exe)
    if version != FLAWFINDER_VERSION:
        raise RungError(f"flawfinder {version!r} found, {FLAWFINDER_VERSION} pinned (D-030)")
    work_dir = Path(work_dir)
    shutil.rmtree(work_dir, ignore_errors=True)
    levels: dict[str, dict[str, int | None]] = {}
    for stem, prog in progs.items():
        fns = {f["addr"]: f for f in prog["functions"] if f["in_scope"]}
        (work_dir / stem).mkdir(parents=True)
        levels[stem] = {}
        for addr in walked_functions(prog):
            text = fns[addr].get("pseudo_c")
            if text is None:
                raise RungError(f"{stem} {addr}: walked function without pseudo-C")
            (work_dir / stem / f"{addr}.c").write_text(unalias(text) + "\n", encoding="utf-8")
            levels[stem][addr] = None
    proc = subprocess.run([exe, "--csv", "."], cwd=work_dir, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RungError(f"flawfinder exited {proc.returncode}: {proc.stderr.strip()[:200]}")
    lines = proc.stdout.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("File,")), None)
    if start is None:
        raise RungError("flawfinder printed no CSV header")
    for row in csv.DictReader(io.StringIO("\n".join(lines[start:]))):
        parts = row["File"].removeprefix("./").split("/")
        if len(parts) != 2 or not parts[1].endswith(".c"):
            raise RungError(f"unmapped flawfinder hit in {row['File']!r}")
        stem, addr = parts[0], parts[1][:-2]
        if stem not in levels or addr not in levels[stem]:
            raise RungError(f"unmapped flawfinder hit in {row['File']!r}")
        lvl = int(row["Level"])
        cur = levels[stem][addr]
        levels[stem][addr] = lvl if cur is None else max(cur, lvl)
    return levels


def _rule_doc(rung: str, score_scale: str | None, identity: dict[str, Any],
              programs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"rung": rung, "kind": "rule", "score_scale": score_scale, "definition": DEFINITIONS[rung],
            "identity": identity, "programs": programs}


def rule_rung_docs(programs_dir: Path, work_dir: Path) -> dict[str, dict[str, Any]]:
    """R1, R2 and R3 for every program in programs_dir. Deterministic; no timestamps."""
    progs = load_programs(programs_dir)
    levels = flawfinder_levels(progs, Path(work_dir) / "flawfinder")
    r1: dict[str, dict[str, Any]] = {}
    r2: dict[str, dict[str, Any]] = {}
    r3: dict[str, dict[str, Any]] = {}
    for stem, prog in progs.items():
        sha = prog["binary"]["sha256"]
        graph = build_graph(prog)
        fns = {f["addr"]: f for f in prog["functions"] if f["in_scope"]}
        lv = levels[stem]
        a1: dict[str, Any] = {}
        a2: dict[str, Any] = {}
        a3: dict[str, Any] = {}
        for addr in walked_functions(prog):
            own = lv[addr]
            a1[addr] = _row(own is not None, own or 0)
            names = {unalias(c["name"]) for c in fns[addr]["callees"] if c["kind"] == "external" and c.get("name")}
            a2[addr] = _row(bool(names & INPUT_CALLS), None)
            reach = _reachable(graph.succ, addr)
            outside = sorted(reach - set(lv), key=addr_key)
            if outside:
                raise RungError(f"{stem} {addr}: reaches functions outside the walk {outside[:3]}")
            hits = [lv[a] for a in reach if lv[a] is not None]
            a3[addr] = _row(bool(hits), max(hits, default=0))
        r1[sha], r2[sha], r3[sha] = a1, a2, a3
    ff = {"tool": "flawfinder", "version": FLAWFINDER_VERSION, "options": "defaults",
          "alias_adapter": ALIAS.pattern}
    return {
        "R1": _rule_doc("R1", "ordinal", ff, r1),
        "R2": _rule_doc("R2", None, {"input_calls": sorted(INPUT_CALLS), "alias_adapter": ALIAS.pattern}, r2),
        "R3": _rule_doc("R3", "ordinal", {**ff, "graph": "in-scope call graph (callgraph.build_graph)"}, r3),
    }


def write_rule_rungs(programs_dir: Path, out_dir: Path) -> list[Path]:
    """runs/<id>/R1.json, R2.json, R3.json (and the flawfinder input tree under flawfinder/)."""
    docs = rule_rung_docs(programs_dir, Path(out_dir))
    return [write_doc(d, Path(out_dir) / f"{k}.json") for k, d in docs.items()]


# ---- R4-R7 ----------------------------------------------------------------------------------

def _stem(sha: str, addr: str) -> str:
    """analysis/analyze_one.stem, restated: importing that module would load taintwalk.llm."""
    return f"{sha[:12]}_{addr}"


def _row_from_file(path: Path, addr: str) -> dict[str, Any]:
    if not path.exists():
        raise RungError(f"{path} is missing")
    row = json.loads(path.read_text(encoding="utf-8"))
    rec = row.get("record")
    if rec is None:
        return {"outcome": "abstain", "score": None, "verdict": None}
    if rec["address"] != addr:
        raise RungError(f"{path.name} holds the record of {rec['address']}, not {addr}")
    SummaryRecord.model_validate(rec)
    v = rec["summary"]["verdict"]
    return row_from_finding({"status": "ok", **{k: v[k] for k in VERDICT_FIELDS}})


def llm_rung_doc(root: Path, rung: str) -> dict[str, Any]:
    """R4-R7 from every walk run dir at or under root. The walk arm (R5, R7) is the findings; the
    no-context arm (R4, R6) takes each baseline/ row, and the walk row only where the walk prompt had
    no callee block. The run's provider must match the rung's."""
    if rung not in LLM_RUNGS:
        raise RungError(f"{rung} is not an LLM rung")
    arm, provider = LLM_RUNGS[rung]
    runs = discover_runs(Path(root))
    if not runs:
        raise RungError(f"no walk run dirs at or under {root}")
    identity: dict[str, Any] | None = None
    programs: dict[str, dict[str, Any]] = {}
    for d in runs:
        f = build_findings(d)
        ident = {k: f[k] for k in ("provider", "prompt_version", "callee_context_version")}
        got = ident["provider"].get("provider") if isinstance(ident["provider"], dict) else None
        if got != provider:
            raise RungError(f"{rung} is the {provider} rung, but {d.name} was walked by {got!r}")
        if identity is None:
            identity = ident
        elif ident != identity:
            raise RungError(f"{d.name}: produced by {ident}, earlier runs by {identity}; never pooled")
        sha = f["binary_sha256"]
        if sha in programs:
            raise RungError(f"{d.name}: binary {sha[:12]} appears in two run dirs")
        rows = {r["address"]: row_from_finding(r) for r in f["findings"]}
        if arm == "baseline":
            walk = json.loads((d / "walk.json").read_text(encoding="utf-8"))
            base = walk.get("baseline") or {}
            if not base:
                raise RungError(f"{d.name}: no baseline rows; the no-context arm needs walk --with-baseline")
            stray = sorted(set(base) - set(walk["functions"]), key=addr_key)
            if stray:
                raise RungError(f"{d.name}: baseline rows for functions the walk did not analyze {stray[:3]}")
            for a, fn in walk["functions"].items():
                if a in base:
                    if not fn["context_chars"]:
                        raise RungError(f"{d.name} {a}: a baseline row for a function whose walk prompt "
                                        "had no callee block")
                    row = _row_from_file(d / "baseline" / "summaries" / f"{_stem(sha, a)}.json", a)
                    if (row["outcome"] == "abstain") != (base[a]["status"] != "ok"):
                        raise RungError(f"{d.name} {a}: walk.json says {base[a]['status']!r} for the "
                                        "baseline row, the row file disagrees")
                    rows[a] = row
                elif fn["context_chars"]:
                    raise RungError(f"{d.name} {a}: callee context but no baseline row")
        programs[sha] = rows
    return {"rung": rung, "kind": "llm", "score_scale": "probability", "definition": DEFINITIONS[rung],
            "identity": {**(identity or {}), "arm": arm}, "programs": programs}