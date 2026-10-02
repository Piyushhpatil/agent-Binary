"""Phase 9: freeze the real-code corpus and run screen S6 (D-009, D-037, D-038). Evaluation side.

Input: runs/p9-screen/<project>/screen.json for the four pre-registered projects and the reserve, lua
(D-039). Every pair that passed S1-S5 and S7
enters, and this module:
  1. names every distinct binary opaquely (rw-NNNN, in order of first use by the sorted pairs) and writes
     corpus/real/manifest.json: one entry per binary in the Juliet manifest's shape, so
     `taintwalk corpus verify --manifest corpus/real/manifest.json` proves G1/G2 for it and the leak gate
     reads its name layer from it, plus the pairs;
  2. copies each binary's program.json to runs/p9-real/programs/<case>.json;
  3. runs S6 (D-038): every function with pseudo-C in each root's downward closure gets its full base
     prompt from analysis/prompts.build_prompt, which redacts and then gates it with both layers;
  4. records S6 in the manifest and writes runs/p9-real/programs.txt ("path root,root" per binary),
     holding only the binaries and roots of pairs that passed every screen.
No timestamps: an unchanged input rewrites byte-identical files.

usage: python -m taintwalk.corpus.real_freeze
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from taintwalk.analysis.callgraph import addr_key, build_graph, downward_closure
from taintwalk.analysis.prompts import build_prompt
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.corpus.groundtruth import text_info_path
from taintwalk.corpus.real_screen import CFLAGS, SCREEN_VERSION
from taintwalk.corpus.real_screen import OUT as SCREEN_OUT
from taintwalk.extract.ghidra_runner import sha256_file
from taintwalk.util.leakcheck import LeakError

MANIFEST_SCHEMA = 1
PROJECTS = ("mujs", "md4c", "giflib", "jbig2dec", "lua")   # lua last: the reserve's pairs follow (D-039)
REAL_RUN = REPO_ROOT / "runs" / "p9-real"
CENSUS = REPO_ROOT / "runs" / "p9-census" / "census.json"
RESERVE_CENSUS = REPO_ROOT / "runs" / "p9-census-lua" / "census.json"
MIN_PAIRS = 10                       # pre-registered: below this, the Lua reserve is added by ADR


class FreezeError(RuntimeError):
    """The corpus cannot be frozen exactly; the run stops."""


def _rel(p: Path) -> str:
    return Path(p).resolve().relative_to(REPO_ROOT).as_posix()


def _first_line(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()[0]


def _write(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def _build_dir(project: str, commit: str) -> Path:
    return SCREEN_OUT / "build" / f"{project}-{commit[:12]}"


def load_pairs() -> tuple[list[dict[str, Any]], dict[str, str]]:
    pairs: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for proj in PROJECTS:
        p = SCREEN_OUT / proj / "screen.json"
        if not p.exists():
            raise FreezeError(f"{p} is missing; screen {proj} first")
        digests[proj] = sha256_file(p)
        doc = json.loads(p.read_text(encoding="utf-8"))
        if doc.get("screen_version") != SCREEN_VERSION:
            raise FreezeError(f"{p}: screen_version {doc.get('screen_version')}, expected {SCREEN_VERSION}")
        pairs += [{"project": proj, **r} for r in doc["pairs"] if r["excluded_by"] is None]
    pairs.sort(key=lambda r: (PROJECTS.index(r["project"]), r["cve"]))
    return pairs, digests


def binary_entry(case: str, project: str, commit: str) -> dict[str, Any]:
    d = _build_dir(project, commit)
    meta = json.loads((d / "build.json").read_text(encoding="utf-8"))
    elf, st, prog = d / "bin.elf", d / "bin.stripped.elf", d / "program.json"
    missing = [p.name for p in (elf, st, prog) if not p.is_file()]
    if missing:
        raise FreezeError(f"{d.name}: missing {missing}")
    if meta["exit"] != 0 or meta["g2"] is not True or meta["commit"] != commit:
        raise FreezeError(f"{d.name}: build.json does not record a good build of {commit[:10]}")
    stripped_sha = sha256_file(st)
    if json.loads(prog.read_text(encoding="utf-8"))["binary"]["sha256"] != stripped_sha:
        raise FreezeError(f"{d.name}: program.json was extracted from a different binary")
    return {"case_id": case, "project": project, "commit": commit, "elf": _rel(elf), "stripped": _rel(st),
            "elf_sha256": sha256_file(elf), "stripped_sha256": stripped_sha, "text": text_info_path(elf),
            "build_cmd": meta["cmd"], "functions": [], "source_files": [], "deny": []}


def _root_record(project: str, commit: str, root_key: str) -> dict[str, Any]:
    fns = json.loads((_build_dir(project, commit) / "fns.json").read_text(encoding="utf-8"))
    hits = [f for f in fns if f["key"] == root_key]
    if len(hits) != 1:
        raise FreezeError(f"{project}-{commit[:10]}: {len(hits)} DWARF functions are {root_key}")
    return hits[0]


def s6_side(prog: dict[str, Any], sha: str, root_addr: str) -> dict[str, Any]:
    """Gate the full base prompt of every function in the root's downward closure (D-038)."""
    fmap = {f["addr"]: f for f in prog["functions"]}
    closure = sorted(downward_closure(build_graph(prog), (root_addr,)), key=addr_key)
    gated = redactions = 0
    leaks: list[dict[str, Any]] = []
    for a in closure:
        f = fmap[a]
        if not f.get("pseudo_c"):
            continue                                     # decompile failed: never sent to a model
        gated += 1
        try:
            redactions += build_prompt(f["ghidra_name"], f["pseudo_c"], binary_sha256=sha).redactions
        except LeakError as e:
            leaks.append({"addr": a, "findings": sorted({f"{x.layer}:{x.pattern}:{x.match}"
                                                         for x in e.findings})[:5]})
    return {"closure": len(closure), "gated": gated, "redactions": redactions, "leaks": leaks}


def freeze() -> dict[str, Any]:
    real_cfg = load_config().get("real") or {}
    if not real_cfg.get("manifest"):
        raise FreezeError("config/default.yaml has no real.manifest")
    out = REPO_ROOT / real_cfg["manifest"]
    pairs, digests = load_pairs()
    if not pairs:
        raise FreezeError("no pair passed S1-S5 and S7")

    entries: dict[tuple[str, str], dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    for i, r in enumerate(pairs, 1):
        file, name = r["root"].split(":", 1)
        rec: dict[str, Any] = {"pair_id": f"rp-{i:02d}", "cve": r["cve"], "aliases": list(r.get("aliases", [])),
                               "project": r["project"], "root": name, "file": file, "fix": r["fix"],
                               "pre_commit": r["pre"], "s6": None, "excluded_by": None}
        for side, commit, label in (("pre", r["pre"], "bad"), ("post", r["fix"], "good")):
            key = (r["project"], commit)
            if key not in entries:
                entries[key] = binary_entry(f"rw-{len(entries) + 1:04d}", r["project"], commit)
            e = entries[key]
            f = _root_record(r["project"], commit, r["root"])
            addr = hex(f["lo"])
            if addr != r["sides"][side]["addr"]:
                raise FreezeError(f"{r['cve']} {side}: DWARF says {addr}, the screen recorded "
                                  f"{r['sides'][side]['addr']}")
            if any(x["addr_hex"] == addr for x in e["functions"]):
                raise FreezeError(f"{e['case_id']}: {addr} would be the root of two pairs")
            e["functions"].append({"name": name, "addr": f["lo"], "addr_hex": addr, "size": f["hi"] - f["lo"],
                                   "label": label, "role": "root", "cu": file, "pair": rec["pair_id"]})
            if file not in e["source_files"]:
                e["source_files"].append(file)
            for c in [r["cve"], *r.get("aliases", [])]:
                if c not in e["deny"]:
                    e["deny"].append(c)
            rec[side], rec[f"{side}_addr"] = e["case_id"], addr
        records.append(rec)
    for e in entries.values():
        e["functions"].sort(key=lambda x: x["addr"])
        e["source_files"].sort()
        e["deny"].sort()

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "kind": "real-code pairs (Phase 9, D-009, D-037, D-038)",
        "toolchain": {"gcc": _first_line(["gcc", "--version"]), "strip": _first_line(["strip", "--version"]),
                      "cflags": list(CFLAGS)},
        "inputs": {"census_sha256": sha256_file(CENSUS), "reserve_census_sha256": sha256_file(RESERVE_CENSUS),
                   "screen_sha256": digests,
                   "screen_version": SCREEN_VERSION},
        "label_rules": ("per pair, the root is the one function the fix changes (S2); it is labelled bad in "
                        "the build of the fix's first parent and good in the build of the fix commit"),
        "pairs": records,
        "entries": sorted(entries.values(), key=lambda x: x["case_id"]),
    }
    _write(out, manifest)                            # the gate's name layer reads this file (S6, walks)

    progs_dir = REAL_RUN / "programs"
    shutil.rmtree(progs_dir, ignore_errors=True)
    progs_dir.mkdir(parents=True)
    progs: dict[str, dict[str, Any]] = {}
    for e in manifest["entries"]:
        src = REPO_ROOT / Path(e["stripped"]).parent / "program.json"
        shutil.copyfile(src, progs_dir / f"{e['case_id']}.json")
        progs[e["case_id"]] = json.loads(src.read_text(encoding="utf-8"))

    by_case = {e["case_id"]: e for e in manifest["entries"]}
    for rec in records:
        res = {side: s6_side(progs[rec[side]], by_case[rec[side]]["stripped_sha256"], rec[f"{side}_addr"])
               for side in ("pre", "post")}
        ok = not res["pre"]["leaks"] and not res["post"]["leaks"]
        rec["s6"] = {"pass": ok, **res}
        if not ok:
            rec["excluded_by"] = "S6"
    _write(out, manifest)

    roots: dict[str, set[str]] = {}
    for rec in records:
        if rec["excluded_by"] is None:
            for side in ("pre", "post"):
                roots.setdefault(rec[side], set()).add(rec[f"{side}_addr"])
    lines = [f"{_rel(progs_dir / f'{case}.json')} {','.join(sorted(rs, key=addr_key))}"
             for case, rs in sorted(roots.items())]
    (REAL_RUN / "programs.txt").write_text(
        "# Phase 9 walk list (D-036): a program, then the roots walked in it\n" + "\n".join(lines) + "\n",
        encoding="utf-8")
    manifest["_out"] = str(out)
    return manifest


def report(m: dict[str, Any]) -> int:
    print(f"{'pair':<6} {'cve':<15} {'project':<9} {'root':<34} {'pre':<8} {'post':<8} {'closure':<9} S6")
    for r in m["pairs"]:
        s = r["s6"]
        red = s["pre"]["redactions"] + s["post"]["redactions"]
        print(f"{r['pair_id']:<6} {r['cve']:<15} {r['project']:<9} {r['root'][:34]:<34} {r['pre']:<8} "
              f"{r['post']:<8} {str(s['pre']['closure']) + '/' + str(s['post']['closure']):<9} "
              f"{'ok' if s['pass'] else 'FAIL'}" + (f"  (literals redacted: {red})" if red else ""))
        for side in ("pre", "post"):
            for leak in s[side]["leaks"][:3]:
                print(f"         {side} {leak['addr']}: {leak['findings']}")
    final = [r for r in m["pairs"] if r["excluded_by"] is None]
    used = {r[s] for r in final for s in ("pre", "post")}
    print(f"\n[freeze] {len(m['pairs'])} pairs passed S1-S5 and S7; {len(final)} pass S6; "
          f"{len(used)} binaries to walk, {2 * len(final)} roots")
    print(f"manifest           : {m['_out']}")
    print(f"walk list          : {REAL_RUN / 'programs.txt'}")
    if len(final) < MIN_PAIRS:
        print(f"[freeze] SHORTFALL: {len(final)} pairs < {MIN_PAIRS} with the reserve included; disclosed, "
              "and no other project may be added (D-039)")
    print("FREEZE OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return report(freeze())
    except FreezeError as e:
        print(f"FREEZE FAIL: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())