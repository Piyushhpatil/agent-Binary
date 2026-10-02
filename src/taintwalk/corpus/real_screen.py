"""Phase 9 screens for the real-code corpus (D-009, D-037). Evaluation side: it reads the census.

For every census candidate of one project:
  S1  both commits resolve in the recorded repository;
  S3  pre (the fix's parent) and post (the fix) build with the project's recipe, gcc 15 and the D-014
      flags plus -g -O0 -fno-inline; a stripped copy is made (G1), and .text is identical between each
      build and its copy (G2);
  S2  the fix's changed lines, mapped through each build's DWARF line table, touch exactly one function;
      outside every function only blank and comment-only lines are ignored (D-037);
  S4  Ghidra recovers the root at its DWARF address, in scope and decompiled, in both builds;
  S5  the root's pseudo-C differs between pre and post once addresses inside names are normalised;
  S6  the leak gate: pending, it needs the real-code manifest (mini-step 8);
  S7  no later fix of any census CVE changes the root, and no incomplete-fix follow-up supersedes it
      (D-037). A later fix that does not build makes S7 undecidable, which excludes.
Screens run in dependency order (S1, S3, S2, S4, S5, S7); a pair is excluded at its first failure.

Builds live in runs/p9-screen/build/<project>-<commit12>/ and are reused, so a commit shared by two
pairs (one pair's post is another's pre) is built and extracted once. Names carry commit hashes, never
CVE ids, and sources compile from the tree root with relative paths (D-037 build hygiene).

Each project has one recipe for all of its commits. --validate-recipes builds the project's current head
and the nearest release tag below every candidate, never a candidate commit, so a recipe is never tuned
on the trees being screened.

usage:
  python -m taintwalk.corpus.real_screen --validate-recipes [--project P]
  python -m taintwalk.corpus.real_screen --project P
"""
from __future__ import annotations

import argparse
import difflib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from elftools.elf.elffile import ELFFile

from taintwalk.analysis.callgraph import build_graph
from taintwalk.config import REPO_ROOT, load_config
from taintwalk.corpus.groundtruth import CONST_FORMS, text_info_path
from taintwalk.extract.ghidra_runner import extract_one

SCREEN_VERSION = 1
CENSUS = REPO_ROOT / "runs" / "p9-census" / "census.json"
SRC = REPO_ROOT / "runs" / "p9-spike" / "src"
OUT = REPO_ROOT / "runs" / "p9-screen"
CFLAGS = ("-g", "-O0", "-fno-inline", "-fstack-protector-strong", "-fcf-protection=full",
          "-fPIE", "-pie", "-U_FORTIFY_SOURCE")              # D-014 + -g -O0 -fno-inline
BUILD_TIMEOUT_S = 600
EXTRACT_TIMEOUT_S = 1800
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
COMMENT_ONLY = ("//", "/*", "*")                              # "*/" also starts with "*" (D-037)
ADDR_SUFFIX = re.compile(r"_[0-9a-f]{8,16}\b")                # FUN_00101a2b, DAT_..., LAB_... -> _X


class ScreenError(RuntimeError):
    """The screen cannot run at all (missing census, repository or recipe)."""


# ---- recipes: tree -> (sources relative to the tree, extra flags, libraries) ---------------------

Recipe = Callable[[Path], tuple[list[str], list[str], list[str]]]


def _rel(tree: Path, paths: Any) -> list[str]:
    return sorted(str(p.relative_to(tree)) for p in paths)


def recipe_mujs(tree: Path) -> tuple[list[str], list[str], list[str]]:
    """Every js*.c, utf*.c and regexp.c plus main.c, as mujs's Makefile builds the interpreter.
    one.c (the amalgamation) and pp.c (a second program) are left out."""
    files = {p for pat in ("js*.c", "utf*.c", "regexp.c", "main.c") for p in tree.glob(pat)}
    return _rel(tree, files), [], ["-lm"]


def recipe_md4c(tree: Path) -> tuple[list[str], list[str], list[str]]:
    """The library plus the md2html program. The library moved from md4c/ to src/ in 2019."""
    lib = "md4c" if (tree / "md4c" / "md4c.c").exists() else "src"
    files = [p for d in (lib, "md2html") for p in (tree / d).glob("*.c")]
    return _rel(tree, files), [f"-I{lib}", "-Imd2html"], []


GIF_LIB = ("dgif_lib.c", "egif_lib.c", "gifalloc.c", "gif_err.c", "gif_font.c", "gif_hash.c",
           "openbsd-reallocarray.c", "quantize.c")
GIF_UTIL = ("gif2rgb.c", "getarg.c", "qprintf.c", "quantize.c")


def recipe_giflib(tree: Path) -> tuple[list[str], list[str], list[str]]:
    """The library sources of giflib's Makefile plus the gif2rgb program and its helpers. Older trees
    keep them in lib/ and util/, newer ones flat; every other utility has its own main()."""
    split = (tree / "lib").is_dir()
    lib, util = (tree / "lib", tree / "util") if split else (tree, tree)
    files: list[Path] = []
    seen: set[str] = set()
    for d, names in ((lib, GIF_LIB), (util, GIF_UTIL)):
        for n in names:
            if (d / n).exists() and n not in seen:
                seen.add(n)
                files.append(d / n)
    return _rel(tree, files), (["-Ilib", "-Iutil"] if split else ["-I."]), ["-lm"]


def recipe_jbig2dec(tree: Path) -> tuple[list[str], list[str], list[str]]:
    """Every jbig2*.c (the library and the jbig2dec program) except the PNG writer, which needs libpng,
    plus sha1.c and memento.c when present. HAVE_STDINT_H stands in for the configure step."""
    files = [p for p in tree.glob("jbig2*.c") if p.name != "jbig2_image_png.c"]
    files += [tree / n for n in ("sha1.c", "memento.c") if (tree / n).exists()]
    return _rel(tree, files), ["-DHAVE_STDINT_H"], ["-lm"]


RECIPES: dict[str, Recipe] = {"giflib": recipe_giflib, "jbig2dec": recipe_jbig2dec,
                              "md4c": recipe_md4c, "mujs": recipe_mujs}
HEAD_REF = {"giflib": "origin/HEAD", "jbig2dec": "origin/HEAD", "md4c": "origin/HEAD",
            "mujs": "codeberg/HEAD"}                          # GitHub's mujs HEAD is a migration stub


# ---- git ------------------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, errors="replace")


def git(repo: Path, *args: str) -> str:
    r = _git(repo, *args)
    if r.returncode != 0:
        raise ScreenError(f"git {' '.join(args[:3])}: {r.stderr.strip()[:200]}")
    return r.stdout


def rev(repo: Path, ref: str) -> str | None:
    r = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def is_ancestor(repo: Path, a: str, b: str) -> bool:
    return _git(repo, "merge-base", "--is-ancestor", a, b).returncode == 0


def changed_c_files(repo: Path, sha: str) -> set[str]:
    parent = rev(repo, f"{sha}^1")
    if parent is None:
        return set()
    return {Path(p).name for p in git(repo, "diff", "--name-only", parent, sha, "--", "*.c").split()}


def _export(repo: Path, sha: str, dest: Path) -> None:
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    data = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", sha],
                          capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        tf.extractall(dest, filter="data")


# ---- DWARF ----------------------------------------------------------------------------------

def function_lines(elf_path: Path) -> list[dict[str, Any]]:
    """Every DWARF subprogram with code: its home file and line range, from the line table."""
    out: list[dict[str, Any]] = []
    with open(elf_path, "rb") as fh:
        dw = ELFFile(fh).get_dwarf_info()
        for cu in dw.iter_CUs():
            lp = dw.line_program_for_CU(cu)
            if lp is None:
                continue
            v5 = lp.header["version"] >= 5
            fe = lp.header["file_entry"]

            def fname(i: int) -> str:
                idx = i if v5 else i - 1
                return Path(fe[idx].name.decode(errors="replace")).name if 0 <= idx < len(fe) else "?"

            rows = [(e.state.address, e.state.line, fname(e.state.file))
                    for e in lp.get_entries() if e.state is not None and not e.state.end_sequence]
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                hp = die.attributes.get("DW_AT_high_pc")
                nm = die.attributes.get("DW_AT_name")
                if hp is None or nm is None:
                    continue
                lo = die.attributes["DW_AT_low_pc"].value
                hi = lo + hp.value if hp.form in CONST_FORMS else hp.value
                mine = [(ln, f) for a, ln, f in rows if lo <= a < hi and ln > 0]
                if not mine:
                    continue
                home = Counter(f for _, f in mine).most_common(1)[0][0]
                lines = [ln for ln, f in mine if f == home]
                dl = die.attributes.get("DW_AT_decl_line")
                name = nm.value.decode(errors="replace")
                out.append({"key": f"{home}:{name}", "name": name, "file": home, "lo": lo, "hi": hi,
                            "first": min(lines + ([dl.value] if dl is not None else [])),
                            "last": max(lines)})
    return out


def load_fns(b: dict[str, Any]) -> list[dict[str, Any]]:
    return json.loads((Path(b["dir"]) / "fns.json").read_text(encoding="utf-8"))


# ---- builds ---------------------------------------------------------------------------------

def build(project: str, repo: Path, sha: str) -> dict[str, Any]:
    """Build one commit with the project's recipe; reuse a finished build made with the same command."""
    d = OUT / "build" / f"{project}-{sha[:12]}"
    tree, meta_p = d / "tree", d / "build.json"
    if not tree.is_dir():
        _export(repo, sha, tree)
    srcs, extra, libs = RECIPES[project](tree)
    cmd = ["gcc", *CFLAGS, *extra, "-o", "../bin.elf", *srcs, *libs]
    if meta_p.exists():
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        if meta.get("cmd") == cmd and (meta["exit"] != 0 or (d / "fns.json").exists()):
            return {**meta, "dir": str(d)}
    try:
        r = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, timeout=BUILD_TIMEOUT_S)
        rc, errs = r.returncode, [l for l in r.stderr.splitlines() if "error" in l]
    except subprocess.TimeoutExpired:
        rc, errs = -1, [f"timeout after {BUILD_TIMEOUT_S} s"]
    meta = {"project": project, "commit": sha, "cmd": cmd, "sources": len(srcs), "exit": rc,
            "errors": errs[:5], "error_count": len(errs), "g2": None}
    if rc == 0:
        elf, st = d / "bin.elf", d / "bin.stripped.elf"
        shutil.copy2(elf, st)                                 # G1: copy the one artifact, strip the copy
        subprocess.run(["strip", str(st)], check=True)
        meta["g2"] = text_info_path(elf) == text_info_path(st)
        (d / "fns.json").write_text(json.dumps(function_lines(elf), sort_keys=True) + "\n", encoding="utf-8")
    meta_p.write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return {**meta, "dir": str(d)}


# ---- S2: changed lines -> functions --------------------------------------------------------

def changed_lines(repo: Path, parent: str, sha: str) -> dict[str, dict[str, Any]]:
    """Per changed .c file: non-blank changed line numbers on each side, plus both texts."""
    out: dict[str, dict[str, Any]] = {}
    for path in git(repo, "diff", "--name-only", parent, sha, "--", "*.c").split():
        diff = git(repo, "diff", "-U0", "--no-color", parent, sha, "--", path)
        texts: dict[str, list[str]] = {}
        for side, ref in (("old", parent), ("new", sha)):
            r = _git(repo, "show", f"{ref}:{path}")
            texts[side] = r.stdout.split("\n") if r.returncode == 0 else []
        olds: list[int] = []
        news: list[int] = []
        for line in diff.splitlines():
            m = HUNK.match(line)
            if not m:
                continue
            a, b = int(m[1]), (int(m[2]) if m[2] is not None else 1)
            c, d = int(m[3]), (int(m[4]) if m[4] is not None else 1)
            olds += [i for i in range(a, a + b) if 0 < i <= len(texts["old"]) and texts["old"][i - 1].strip()]
            news += [i for i in range(c, c + d) if 0 < i <= len(texts["new"]) and texts["new"][i - 1].strip()]
        out[path] = {"old": olds, "new": news, "old_text": texts["old"], "new_text": texts["new"]}
    return out


def touched(fns: list[dict[str, Any]], path: str, lines: list[int],
            text: list[str]) -> tuple[set[str], list[str]]:
    """Functions owning the changed lines, and changed lines outside every function that are not
    comment-only (D-037)."""
    base = Path(path).name
    cand = [f for f in fns if f["file"] == base]
    hit: set[str] = set()
    outside: list[str] = []
    for ln in lines:
        owners = [f["key"] for f in cand if f["first"] <= ln <= f["last"]]
        if owners:
            hit.update(owners)
            continue
        s = text[ln - 1].strip()
        if not s.startswith(COMMENT_ONLY):
            outside.append(f"{base}:{ln}: {s[:70]}")
    return hit, outside


def map_change(repo: Path, parent: str, sha: str, b_parent: dict[str, Any],
               b_sha: dict[str, Any]) -> tuple[set[str], set[str], list[str]]:
    fp, fs = load_fns(b_parent), load_fns(b_sha)
    kp: set[str] = set()
    ks: set[str] = set()
    outside: list[str] = []
    for path, x in changed_lines(repo, parent, sha).items():
        h, o = touched(fp, path, x["old"], x["old_text"])
        kp |= h
        outside += [f"pre {s}" for s in o]
        h, o = touched(fs, path, x["new"], x["new_text"])
        ks |= h
        outside += [f"post {s}" for s in o]
    return kp, ks, outside


# ---- S4/S5: extraction and the root ----------------------------------------------------------

def extract(b: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    d = Path(b["dir"])
    out = d / "program.json"
    res = extract_one(d / "bin.stripped.elf", out,
                      decompile_timeout=load_config()["extract"]["decompile_timeout_s"],
                      binary_timeout=EXTRACT_TIMEOUT_S)
    info = {"status": res.status, "seconds": round(res.seconds, 1)}
    return info, (json.loads(out.read_text(encoding="utf-8")) if res.ok else None)


def root_stats(prog: dict[str, Any], addr: str) -> tuple[dict[str, Any], str] | None:
    """The root's size and its downward closure in the in-scope call graph: what the walk will cost."""
    fmap = {f["addr"]: f for f in prog["functions"]}
    fn = fmap.get(addr)
    if fn is None or not fn["in_scope"] or not fn.get("pseudo_c"):
        return None
    g = build_graph(prog)
    seen, stack = {addr}, [addr]
    while stack:
        for c in g.succ.get(stack.pop(), ()):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return ({"addr": addr, "root_chars": len(fn["pseudo_c"]), "closure": len(seen),
             "closure_chars": sum(len(fmap[a].get("pseudo_c") or "") for a in seen),
             "max_fanout": max(len(g.succ[a]) for a in seen),
             "indirect_sites": sum(fmap[a]["indirect_call_sites"] for a in seen),
             "decompile_failed": sum(bool(fmap[a].get("decompile_failed")) for a in seen),
             "in_scope_total": len(g.nodes)}, fn["pseudo_c"])


def changed_after_normalising(a: str, b: str) -> int:
    x, y = (ADDR_SUFFIX.sub("_X", s).splitlines() for s in (a, b))
    return sum(1 for l in difflib.unified_diff(x, y, lineterm="", n=0)
               if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))


# ---- S7 -------------------------------------------------------------------------------------

def screen_s7(c: dict[str, Any], root: str, rows: list[dict[str, Any]], project: str,
              repo: Path) -> dict[str, Any]:
    me = {c["cve"], *c.get("aliases", [])}
    fix = c["fix"]["commit"]
    root_file = root.split(":", 1)[0]
    superseded_by = sorted(r["cve"] for r in rows if r.get("supersedes") in me)
    if superseded_by:
        return {"pass": False, "why": f"an incomplete-fix follow-up supersedes it: {superseded_by}", "checked": []}
    later: set[tuple[str, str]] = set()
    for r in rows:
        if r["cve"] in me:
            continue
        for sha in r.get("s7_commits", []):
            if sha != fix and is_ancestor(repo, fix, sha) and root_file in changed_c_files(repo, sha):
                later.add((sha, r["cve"]))
    checked: list[dict[str, Any]] = []
    for sha, cve in sorted(later):
        parent = rev(repo, f"{sha}^1")
        if parent is None:
            return {"pass": False, "why": f"S7 undecidable: later fix {sha[:10]} ({cve}) has no parent",
                    "checked": checked}
        bp, bc = build(project, repo, parent), build(project, repo, sha)
        if bp["exit"] != 0 or bc["exit"] != 0:
            return {"pass": False, "why": f"S7 undecidable: later fix {sha[:10]} ({cve}) does not build",
                    "checked": checked}
        kp, kc, _ = map_change(repo, parent, sha, bp, bc)
        hit = root in (kp | kc)
        checked.append({"commit": sha[:10], "cve": cve, "touches_root": hit})
        if hit:
            return {"pass": False, "why": f"later fix {sha[:10]} ({cve}) changes the root", "checked": checked}
    return {"pass": True, "checked": checked}


# ---- one candidate --------------------------------------------------------------------------

def screen_candidate(c: dict[str, Any], rows: list[dict[str, Any]], project: str,
                     repo: Path) -> dict[str, Any]:
    fix, pre = c["fix"]["commit"], c["pre_commit"]
    r: dict[str, Any] = {"cve": c["cve"], "aliases": c.get("aliases", []), "fix": fix, "pre": pre,
                         "screens": {}, "excluded_by": None}

    def fail(screen: str, why: str, **extra: Any) -> dict[str, Any]:
        r["screens"][screen] = {"pass": False, "why": why, **extra}
        r["excluded_by"] = screen
        return r

    for sha in (pre, fix):
        if rev(repo, sha) is None:
            return fail("S1", f"{sha[:10]} is not in the repository")
    r["screens"]["S1"] = {"pass": True}

    bp, bf = build(project, repo, pre), build(project, repo, fix)
    for side, b in (("pre", bp), ("post", bf)):
        if b["exit"] != 0:
            return fail("S3", f"{side} does not build ({b['error_count']} errors): {b['errors'][:1]}")
        if not b["g2"]:
            return fail("S3", f"{side}: .text differs between the build and its stripped copy (G2)")
    r["screens"]["S3"] = {"pass": True}

    kp, kf, outside = map_change(repo, pre, fix, bp, bf)
    keys = kp | kf
    s2 = {"pre": sorted(kp), "post": sorted(kf), "outside": outside[:6], "outside_n": len(outside)}
    if len(keys) != 1 or outside:
        return fail("S2", f"touches {sorted(keys)} with {len(outside)} changed lines outside functions", **s2)
    r["screens"]["S2"] = {"pass": True, **s2}
    root = next(iter(keys))
    r["root"] = root

    sides: dict[str, dict[str, Any]] = {}
    texts: dict[str, str] = {}
    for side, b in (("pre", bp), ("post", bf)):
        rec = next((f for f in load_fns(b) if f["key"] == root), None)
        if rec is None:
            return fail("S4", f"{side}: the root is not in this build's DWARF")
        info, prog = extract(b)
        if prog is None:
            return fail("S4", f"{side}: Ghidra {info['status']}")
        st = root_stats(prog, hex(rec["lo"]))
        if st is None:
            return fail("S4", f"{side}: no in-scope decompiled function at {hex(rec['lo'])}")
        sides[side] = {**info, **st[0]}
        texts[side] = st[1]
    r["sides"] = sides
    r["screens"]["S4"] = {"pass": True}

    n = changed_after_normalising(texts["pre"], texts["post"])
    if n == 0:
        return fail("S5", "the decompiled root is identical in pre and post", changed_lines=0)
    r["screens"]["S5"] = {"pass": True, "changed_lines": n}
    r["screens"]["S6"] = {"pass": None, "why": "pending: the leak gate on real code (mini-step 8)"}

    s7 = screen_s7(c, root, rows, project, repo)
    r["screens"]["S7"] = s7
    if not s7["pass"]:
        r["excluded_by"] = "S7"
    return r


def show(r: dict[str, Any]) -> None:
    marks = " ".join(f"{k}:{'ok' if v['pass'] else ('..' if v['pass'] is None else 'FAIL')}"
                     for k, v in r["screens"].items())
    verdict = "PASS (S6 pending)" if r["excluded_by"] is None else f"EXCLUDED at {r['excluded_by']}"
    print(f"\n{r['cve']}  fix {r['fix'][:10]}  pre {r['pre'][:10]}  {marks}  -> {verdict}")
    if r["excluded_by"]:
        print(f"   why: {r['screens'][r['excluded_by']]['why']}")
    if "root" in r:
        print(f"   root {r['root']}")
    for side, x in r.get("sides", {}).items():
        print(f"   {side:<4} ghidra {x['status']} {x['seconds']} s  in-scope {x['in_scope_total']}  root {x['addr']} "
              f"{x['root_chars']} chars  closure {x['closure']} fns / {x['closure_chars']} chars  "
              f"fan-out {x['max_fanout']}  indirect {x['indirect_sites']}")
    s7 = r["screens"].get("S7")
    if s7 and s7.get("checked"):
        print("   S7 later fixes: " + ", ".join(
            f"{x['commit']} {x['cve']} {'ROOT' if x['touches_root'] else 'other fn'}" for x in s7["checked"]))


# ---- recipe validation ----------------------------------------------------------------------

def validate(project: str, repo: Path, cands: list[dict[str, Any]]) -> bool:
    pinned = {c["fix"]["commit"] for c in cands} | {c["pre_commit"] for c in cands}
    refs: dict[str, str] = {}
    if (head := rev(repo, HEAD_REF[project])):
        refs[HEAD_REF[project]] = head
    for c in cands:
        t = _git(repo, "describe", "--tags", "--abbrev=0", c["pre_commit"])
        tag = t.stdout.strip()
        if t.returncode == 0 and tag and (sha := rev(repo, tag)):
            refs.setdefault(tag, sha)
    ok = bool(refs)
    for name, sha in refs.items():
        if sha in pinned:
            print(f"[recipe] {project:<9} {name:<24} skipped: it is a candidate commit")
            continue
        b = build(project, repo, sha)
        good = b["exit"] == 0 and bool(b["g2"])
        ok = ok and good
        print(f"[recipe] {project:<9} {name:<24} {sha[:10]}  exit {b['exit']}  sources {b['sources']}  "
              f"g2 {b['g2']}" + ("" if good else f"  errors {b['error_count']}: {b['errors'][:2]}"))
    return ok


# ---- command line ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m taintwalk.corpus.real_screen",
                               description="Phase 9 screens S1-S5 and S7 (D-009, D-037).")
    p.add_argument("--validate-recipes", action="store_true",
                   help="build each project's head and nearest release tags (never a candidate)")
    p.add_argument("--project", choices=sorted(RECIPES), help="screen this project's candidates")
    a = p.parse_args(argv)
    if not CENSUS.exists():
        print(f"SCREEN FAIL: {CENSUS} is missing; run the census first")
        return 1
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
    if census.get("census_version", 0) < 2:
        print("SCREEN FAIL: the census has no S7 commit sets; re-run python -m taintwalk.corpus.real")
        return 1
    projects = [a.project] if a.project else sorted(RECIPES)
    for proj in projects:
        if not (SRC / proj).is_dir():
            print(f"SCREEN FAIL: no clone at {SRC / proj}")
            return 1

    if a.validate_recipes:
        ok = True
        for proj in projects:
            ok = validate(proj, SRC / proj, [c for c in census["candidates"] if c["project"] == proj]) and ok
        print("RECIPES OK" if ok else "RECIPES FAIL: fix that project's recipe before screening it")
        return 0 if ok else 1
    if not a.project:
        p.error("give --project P, or --validate-recipes")

    proj, repo = a.project, SRC / a.project
    cands = [c for c in census["candidates"] if c["project"] == proj]
    rows = [r for r in census["rows"] if r["project"] == proj and r.get("project_match")]
    results: list[dict[str, Any]] = []
    try:
        for c in cands:
            r = screen_candidate(c, rows, proj, repo)
            results.append(r)
            show(r)
    except ScreenError as e:
        print(f"SCREEN FAIL: {e}")
        return 1
    doc = {"screen_version": SCREEN_VERSION, "project": proj, "cflags": list(CFLAGS),
           "recipe": " ".join((RECIPES[proj].__doc__ or "").split()), "pairs": results}
    out = OUT / proj / "screen.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    passed = [r for r in results if r["excluded_by"] is None]
    print(f"\n[screen] {proj}: {len(results)} candidates, {len(passed)} pass S1-S5 and S7 (S6 pending); "
          f"excluded: {dict(Counter(r['excluded_by'] for r in results if r['excluded_by']))}")
    print(f"screen.json        : {out}")
    print("SCREEN OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())