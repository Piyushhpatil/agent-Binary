"""`taintwalk walk --all`: walk many programs, one `taintwalk walk` subprocess each (Phase 8, D-032).

Label-free: the input is a list of program.json paths (a text file with one path per line, or
a directory of *.json files) and nothing from the evaluation side.

Why one subprocess per program instead of a loop in this process:
- the batch runs exactly the tested single-program command, so a batch run dir is a
  single-program run dir by construction;
- each walk builds its own provider, so every run dir keeps its own usage.json;
- one crashed walk cannot take the batch down.

Layout under ROOT: one run dir per program, named after the program file (what
`taintwalk score ROOT` discovers), logs/<name>.log, and the summary walk_all.json.

A program counts as walked only if its subprocess exits 0 and its log's verdict line is
"WALK OK", the same test as the Phase 7 gate. The batch carries on past a failed program and
exits 1 at the end.

Resumable through the LLM cache: rerunning replays every finished call at zero cost, so an
interrupted batch simply continues. With --offline a replay cannot reach a model at all.
Ctrl+C cancels the programs still queued; the running walks receive the same signal.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from taintwalk.config import REPO_ROOT

LOG_DIR = "logs"
SUMMARY_FILE = "walk_all.json"
# The verdict and token lines that walker.walk_report and cli._cmd_walk print.
WALK_LINE = re.compile(r"^WALK (?:OK|FAIL)\b.*$", re.M)
TOKENS_LINE = re.compile(
    r"^tokens \(this run\)\s*:\s*in (\d+)\s+out (\d+)\s+model time ([\d.]+) s\s+"
    r"cache hits (\d+) of (\d+) calls",
    re.M,
)

Runner = Callable[[list[str], Path], int]


@dataclass(frozen=True)
class WalkResult:
    program: str              # the program.json path as given
    name: str                 # run dir name under the root: the program file's stem
    rc: int                   # subprocess exit code
    status: str               # last verdict line of the log, or "no WALK line"
    ok: bool                  # rc == 0 and status == "WALK OK"
    tokens_in: int | None     # None when the walk printed no token line (it failed early)
    tokens_out: int | None
    model_s: float | None
    cache_hits: int | None
    calls: int | None
    wall_s: float


def _say(line: str) -> None:
    print(line, flush=True)


def read_program_list(src: Path) -> list[Path]:
    """A directory of *.json files (sorted by name), or a text file with one program path per
    line (blank lines and '#' comments skipped, relative paths taken from the repo root).
    Fails before anything runs if the list is empty, a file is missing, or two programs would
    share a run dir."""
    src = Path(src)
    if src.is_dir():
        progs = sorted(src.glob("*.json"))
    elif src.is_file():
        progs = []
        for raw in src.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            p = Path(line)
            progs.append(p if p.is_absolute() else REPO_ROOT / p)
    else:
        raise ValueError(f"program list not found: {src}")
    if not progs:
        raise ValueError(f"no programs in {src}")
    missing = [str(p) for p in progs if not p.is_file()]
    if missing:
        raise ValueError(f"{len(missing)} program file(s) missing, e.g. {missing[0]}")
    shared = sorted(s for s, k in Counter(p.stem for p in progs).items() if k > 1)
    if shared:
        raise ValueError(f"programs share a run dir name: {shared[:3]}")
    return progs


def walk_command(program: Path, run_dir: Path, *, provider: str | None = None,
                 providers_config: Path | None = None, with_baseline: bool = False,
                 offline: bool = False, no_cache: bool = False,
                 retry_failed: bool = False) -> list[str]:
    """The single-program command, exactly as a person would type it."""
    cmd = [sys.executable, "-m", "taintwalk.cli", "walk",
           "--program", str(program), "--run-dir", str(run_dir)]
    if provider:
        cmd += ["--provider", provider]
    if providers_config:
        cmd += ["--providers-config", str(providers_config)]
    if with_baseline:
        cmd.append("--with-baseline")
    if offline:
        cmd.append("--offline")
    if no_cache:
        cmd.append("--no-cache")
    if retry_failed:
        cmd.append("--retry-failed")
    return cmd


def parse_log(text: str) -> dict[str, Any]:
    """The verdict and token counts of one walk log. Missing lines become None."""
    verdicts = WALK_LINE.findall(text)
    t = TOKENS_LINE.search(text)
    return {
        "status": verdicts[-1].strip() if verdicts else "no WALK line",
        "tokens_in": int(t.group(1)) if t else None,
        "tokens_out": int(t.group(2)) if t else None,
        "model_s": float(t.group(3)) if t else None,
        "cache_hits": int(t.group(4)) if t else None,
        "calls": int(t.group(5)) if t else None,
    }


def run_subprocess(cmd: list[str], log: Path) -> int:
    """One walk, stdin closed (it must never consume the caller's input), output in the log."""
    with log.open("w", encoding="utf-8") as fh:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=fh,
                              stderr=subprocess.STDOUT, check=False).returncode


def walk_all(programs: list[Path], root: Path, *, jobs: int = 1, runner: Runner | None = None,
             progress: Callable[[str], None] = _say, **flags: Any) -> list[WalkResult]:
    """Walk every program. Results come back in input order, whatever the completion order."""
    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    run = runner or run_subprocess
    root = Path(root)
    (root / LOG_DIR).mkdir(parents=True, exist_ok=True)
    n = len(programs)

    def one(p: Path) -> WalkResult:
        log = root / LOG_DIR / f"{p.stem}.log"
        t0 = time.monotonic()
        rc = run(walk_command(p, root / p.stem, **flags), log)
        wall = time.monotonic() - t0
        info = parse_log(log.read_text(encoding="utf-8", errors="replace") if log.exists() else "")
        return WalkResult(program=str(p), name=p.stem, rc=rc,
                          ok=rc == 0 and info["status"] == "WALK OK", wall_s=round(wall, 3), **info)

    results: dict[int, WalkResult] = {}
    ex = ThreadPoolExecutor(max_workers=jobs)
    try:
        futures = {ex.submit(one, p): i for i, p in enumerate(programs)}
        for fut in as_completed(futures):
            r = fut.result()
            results[futures[fut]] = r
            tok = "" if r.tokens_in is None else f"  in {r.tokens_in} out {r.tokens_out}"
            progress(f"[{len(results)}/{n}] {r.name}  {r.status}{tok}  {r.wall_s:.1f} s")
    except KeyboardInterrupt:
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    ex.shutdown(wait=True)
    return [results[i] for i in range(n)]


def _totals(results: list[WalkResult]) -> dict[str, Any]:
    return {
        "tokens_in": sum(r.tokens_in or 0 for r in results),
        "tokens_out": sum(r.tokens_out or 0 for r in results),
        "model_s": round(sum(r.model_s or 0.0 for r in results), 1),
        "cache_hits": sum(r.cache_hits or 0 for r in results),
        "calls": sum(r.calls or 0 for r in results),
    }


def write_summary(root: Path, results: list[WalkResult], *, jobs: int, flags: dict[str, Any],
                  wall_s: float) -> Path:
    """ROOT/walk_all.json: one row per program in input order, plus totals. Counts only."""
    doc = {
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "programs": len(results),
        "walk_ok": sum(r.ok for r in results),
        "jobs": jobs,
        "flags": {k: (str(v) if isinstance(v, Path) else v) for k, v in sorted(flags.items())},
        **_totals(results),
        "wall_s": round(wall_s, 1),
        "results": [asdict(r) for r in results],
    }
    out = Path(root) / SUMMARY_FILE
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def run_walk_all(programs_src: Path, root: Path, *, jobs: int = 1, runner: Runner | None = None,
                 **flags: Any) -> int:
    """CLI entry. Exit 0 only if every program is WALK OK; 1 otherwise; 2 on bad usage."""
    if jobs < 1:
        print("WALK ALL FAIL: --jobs must be at least 1")
        return 2
    try:
        programs = read_program_list(programs_src)
    except ValueError as e:
        print(f"WALK ALL FAIL: {e}")
        return 1
    root = Path(root)
    if flags.get("offline"):
        mode = "offline replay (a cache miss fails that program)"
    elif flags.get("no_cache"):
        mode = "live, disk cache OFF"
    else:
        mode = "live, disk cache on"
    _say(f"walk --all: {len(programs)} programs -> {root}  jobs {jobs}  {mode}")
    t0 = time.monotonic()
    results = walk_all(programs, root, jobs=jobs, runner=runner, **flags)
    wall = time.monotonic() - t0
    out = write_summary(root, results, jobs=jobs, flags=flags, wall_s=wall)
    t = _totals(results)
    bad = [r for r in results if not r.ok]
    print(f"\nprograms           : {len(results)}  WALK OK {len(results) - len(bad)}")
    print(f"tokens (all runs)  : in {t['tokens_in']}  out {t['tokens_out']}  model time {t['model_s']:.1f} s  "
          f"cache hits {t['cache_hits']} of {t['calls']} calls")
    print(f"wall time          : {wall:.1f} s")
    print(f"summary            : {out}")
    for r in bad:
        print(f"  NOT OK {r.name}: rc {r.rc}, {r.status}  (log {root / LOG_DIR / (r.name + '.log')})")
    print(f"WALK ALL OK: {len(results)}/{len(results)}" if not bad
          else f"WALK ALL FAIL: {len(results) - len(bad)}/{len(results)} WALK OK")
    return 0 if not bad else 1