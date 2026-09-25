"""Compile the selected Juliet cases and strip a copy of each (Invariant G1, D-005, D-013).

`compile_and_strip` is the ONLY corpus code path that invokes gcc. The stripped file is
always `cp` + `strip` of the artifact that same call just compiled; nothing compiles twice.
Final names are opaque (tw-NNNN) so no label can reach Ghidra via the filename (I1).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from taintwalk.config import REPO_ROOT
from taintwalk.corpus.select import corpus_cfg, digest, select

COMPILE_TIMEOUT_S = 120


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _first_line(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def _rel(p: Path) -> str:
    return p.resolve().relative_to(REPO_ROOT).as_posix()


def _case_tag(case: dict[str, Any]) -> str:
    """Label-free scratch name for a candidate."""
    return hashlib.sha1(json.dumps(case, sort_keys=True).encode()).hexdigest()[:12]


def compile_and_strip(case: dict[str, Any], juliet_root: Path, cflags: list[str],
                      support: list[str], work: Path) -> dict[str, Any]:
    tag = _case_tag(case)
    elf = work / f"{tag}.elf"
    stripped = work / f"{tag}.stripped.elf"
    sup_dir = juliet_root / "testcasesupport"
    cmd = ["gcc", *cflags, f"-I{sup_dir}",
           *[str(sup_dir / s) for s in support],
           *[str(juliet_root / f) for f in case["files"]],
           "-o", str(elf)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=COMPILE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stage": "compile", "error": f"timeout after {COMPILE_TIMEOUT_S} s"}
    if r.returncode != 0:
        return {"ok": False, "stage": "compile", "error": r.stderr[-2000:]}
    shutil.copy2(elf, stripped)                                     # G1: copy the one artifact...
    s = subprocess.run(["strip", str(stripped)], capture_output=True, text=True)  # ...strip the copy
    if s.returncode != 0:
        return {"ok": False, "stage": "strip", "error": s.stderr[-2000:]}
    return {"ok": True, "elf": elf, "stripped": stripped}


def build_corpus(c: dict[str, Any] | None = None, jobs: int | None = None) -> int:
    c = c or corpus_cfg()
    juliet_root = (REPO_ROOT / c["juliet_root"]).resolve()
    build_dir = REPO_ROOT / c["build_dir"]
    work = build_dir / "_work"
    if build_dir.exists():               # build_dir is gitignored and owned by this command
        shutil.rmtree(build_dir)
    work.mkdir(parents=True)

    sel = select(c)
    groups = sel["groups"]
    cflags = [str(x) for x in c["cflags"]]
    support = [str(x) for x in c["support_sources"]]
    jobs = int(jobs or c["jobs"])

    chosen: list[list[tuple[int, dict[str, Any], dict[str, Any]]]] = [[] for _ in groups]
    nxt = [0] * len(groups)
    attempts: list[dict[str, Any]] = []
    t0 = time.monotonic()

    def run(item: tuple[int, int, dict[str, Any]]) -> dict[str, Any]:
        return compile_and_strip(item[2], juliet_root, cflags, support, work)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        while True:
            batch: list[tuple[int, int, dict[str, Any]]] = []
            for gi, g in enumerate(groups):
                want = g["need"] - len(chosen[gi])
                take = g["ranked"][nxt[gi]:nxt[gi] + want] if want > 0 else []
                batch.extend((gi, nxt[gi] + off, case) for off, case in enumerate(take))
                nxt[gi] += len(take)
            if not batch:
                break
            for (gi, rank, case), res in zip(batch, pool.map(run, batch)):
                rec = {"group": gi, "rank": rank, "cwe": case["cwe"],
                       "functional": case["functional"], "flow": case["flow"], "ok": res["ok"]}
                if not res["ok"]:
                    rec.update(stage=res["stage"], error=res["error"])
                attempts.append(rec)
                if res["ok"]:
                    chosen[gi].append((rank, case, res))

    with open(build_dir / "build_log.jsonl", "w", encoding="utf-8") as fh:
        for a in attempts:
            fh.write(json.dumps(a) + "\n")
    failures = [a for a in attempts if not a["ok"]]
    for a in failures:
        first = next((l for l in a["error"].splitlines() if "error" in l), a["error"][:200])
        print(f"  build failure: CWE-{a['cwe']} {a['functional']} flow {a['flow']} "
              f"[{a['stage']}]: {first[:200]}")

    short = [f"CWE-{g['cwe']} flow {g['flow']} {g['stratum']}: built {len(chosen[i])}/{g['need']}"
             for i, g in enumerate(groups) if len(chosen[i]) < g["need"]]
    if short:
        print("BUILD FAIL: pools exhausted:\n  " + "\n  ".join(short))
        return 1

    entries: list[dict[str, Any]] = []
    n = 0
    for gi, g in enumerate(groups):
        for rank, case, res in chosen[gi]:
            n += 1
            cid = f"tw-{n:04d}"
            elf, st = build_dir / f"{cid}.elf", build_dir / f"{cid}.stripped.elf"
            res["elf"].rename(elf)
            res["stripped"].rename(st)
            entries.append({"case_id": cid, **case, "stratum": g["stratum"], "rank": rank,
                            "substituted": rank >= g["need"],
                            "elf": _rel(elf), "stripped": _rel(st),
                            "elf_sha256": _sha256(elf), "stripped_sha256": _sha256(st)})
    shutil.rmtree(work)

    meta = {"schema": 1, "selection_digest": digest(sel), "seed": sel["seed"],
            "juliet_root": c["juliet_root"],
            "gcc": _first_line(["gcc", "--version"]),
            "strip": _first_line(["strip", "--version"]),
            "cflags": cflags, "support_sources": support,
            "attempts": len(attempts), "failures": len(failures),
            "entries": entries}
    (build_dir / "build.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")

    subs = sum(e["substituted"] for e in entries)
    print(f"BUILD: {len(entries)}/{sel['total']} entries from {len(attempts)} compile attempts; "
          f"{len(failures)} failed, {subs} slots substituted; "
          f"{time.monotonic() - t0:.0f}s with {jobs} jobs")
    print(f"toolchain: {meta['gcc']}")
    print(f"wrote {_rel(build_dir / 'build.json')} and {_rel(build_dir / 'build_log.jsonl')}")
    return 0 if len(entries) == sel["total"] else 1
