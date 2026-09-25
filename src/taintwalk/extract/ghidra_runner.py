"""Drive scripts/ghidra_export.py: one subprocess (one JVM) per binary.

Why a subprocess per binary rather than one long-lived JVM:
  * a JVM starts once per process (D-012), and reusing one program context across
    240 binaries leaks analyzer state between them;
  * a hung decompiler is killable with a wall timeout;
  * a crash takes out one binary instead of the whole run.
Cost is ~3 s of JVM startup per binary, parallelised across `extract.jobs`.

Cache key: an existing program.json is reused only if BOTH the input binary's
sha256 AND the exporter fingerprint (ghidra_export.py + schema.py) match. Changing
the exporter invalidates every cached program.json automatically.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from taintwalk.config import REPO_ROOT, load_config

EXPORT_SCRIPT = REPO_ROOT / "scripts" / "ghidra_export.py"
SCHEMA_FILE = Path(__file__).resolve().parent / "schema.py"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def exporter_fingerprint() -> str:
    """sha256 over the code that determines program.json's content."""
    h = hashlib.sha256()
    for p in (EXPORT_SCRIPT, SCHEMA_FILE):
        h.update(p.name.encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


@dataclass
class ExtractResult:
    target: Path
    output: Path
    status: str          # "ok" | "cached" | "timeout" | "failed"
    seconds: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "cached")


def _is_current(out: Path, target: Path) -> bool:
    """True if `out` was produced from these input bytes by this exporter version."""
    if not out.is_file():
        return False
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
        return (
            data["binary"]["sha256"] == sha256_file(target)
            and data["provenance"].get("exporter_sha256") == exporter_fingerprint()
        )
    except (json.JSONDecodeError, KeyError, OSError):
        return False


def extract_one(
    target: Path,
    output: Path,
    *,
    decompile_timeout: int,
    binary_timeout: int,
    force: bool = False,
) -> ExtractResult:
    target = target.resolve()
    if not target.is_file():
        return ExtractResult(target, output, "failed", 0.0, "input does not exist")
    if not force and _is_current(output, target):
        return ExtractResult(target, output, "cached", 0.0)

    project_dir = Path(tempfile.mkdtemp(prefix="tw-ghidra-"))
    cmd = [
        sys.executable,
        str(EXPORT_SCRIPT),
        str(target),
        str(output),
        "--project-dir",
        str(project_dir),
        "--decompile-timeout",
        str(decompile_timeout),
    ]
    t0 = time.perf_counter()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(REPO_ROOT),
            start_new_session=True,          # own process group, so the JVM dies with it
        )
        try:
            out, _ = proc.communicate(timeout=binary_timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return ExtractResult(
                target, output, "timeout", time.perf_counter() - t0,
                f"exceeded {binary_timeout}s",
            )
        dt = time.perf_counter() - t0
        if proc.returncode != 0:
            tail = "\n".join((out or "").strip().splitlines()[-8:])
            return ExtractResult(target, output, "failed", dt, tail)
        return ExtractResult(target, output, "ok", dt, (out or "").strip())
    finally:
        shutil.rmtree(project_dir, ignore_errors=True)


def extract_many(
    targets: list[tuple[str, Path]],
    out_dir: Path,
    *,
    jobs: int,
    decompile_timeout: int,
    binary_timeout: int,
    force: bool = False,
) -> list[ExtractResult]:
    """targets: (case_id, stripped_elf_path). Writes out_dir/programs/<case_id>.json."""
    programs = out_dir / "programs"
    programs.mkdir(parents=True, exist_ok=True)

    def work(item: tuple[str, Path]) -> ExtractResult:
        case_id, path = item
        return extract_one(
            path,
            programs / f"{case_id}.json",
            decompile_timeout=decompile_timeout,
            binary_timeout=binary_timeout,
            force=force,
        )

    results: list[ExtractResult] = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for i, r in enumerate(pool.map(work, targets), 1):
            results.append(r)
            mark = {"ok": "ok", "cached": "cached", "timeout": "TIMEOUT", "failed": "FAILED"}[r.status]
            print(f"[{i}/{len(targets)}] {r.target.name}: {mark} ({r.seconds:.1f}s)", flush=True)
            if not r.ok and r.detail:
                print(f"    {r.detail}", flush=True)
    return results


def extract_cfg() -> dict:
    cfg = load_config()
    e = dict(cfg.get("extract", {}))
    e.setdefault("out_dir", "runs/p2-extract")
    e.setdefault("smoke_dir", "runs/p2-smoke")
    e.setdefault("decompile_timeout_s", 60)
    e.setdefault("binary_timeout_s", 300)
    e.setdefault("jobs", 8)
    e.setdefault("min_recovery", 0.80)
    return e