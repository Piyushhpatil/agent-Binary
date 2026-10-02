"""Phase 9 real-code corpus census (D-009). Evaluation side: it reads CVE metadata, which is
ground truth.

Mechanical selection of (vulnerable, patched) function pairs from real open-source C projects.
Nothing here builds, extracts or calls a model; it decides WHICH candidates exist and writes every
decision with its reason, so the candidate list is reproducible from recorded snapshots.

Run as a module (no CLI subcommand yet):
    python -m taintwalk.corpus.real --fetch      # snapshot NVD + GitHub events, then decide
    python -m taintwalk.corpus.real              # decide from existing snapshots only

Pipeline, fixed by the Phase 9 pre-registration:
    project match -> scope (two signals) -> resolve fix commit (4 ordered sources)
    -> exclude incomplete-fix follow-ups -> collapse shared fix commits -> cap per project (seeded)

Scope needs BOTH signals: the advisory (CWE set + description) and the fix commit's message. An
out-of-scope signal from either side excludes, whatever the other says, because NVD's CWE alone is
wrong often enough to matter (CVE-2022-44789 carries CWE-787 for a use-after-free).

The hunk-header function names recorded per candidate are a PREVIEW. The real single-function screen
(S2) maps changed line ranges through DWARF and lives elsewhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from taintwalk.config import REPO_ROOT

CENSUS_VERSION = 2                  # 2: s7_commits on every project-matched row (D-037)
SEED = 20261001
PER_PROJECT_CAP = 5
MIN_PAIRS = 10                      # below this, the Lua reserve is triggered (pre-registered)

# project -> (CPE product field, GitHub "owner/repo" for issue events or None, clone url)
PROJECTS: dict[str, tuple[str, str | None, str]] = {
    "mujs": ("mujs", "ccxvii/mujs", "https://codeberg.org/ccxvii/mujs"),
    "md4c": ("md4c", "mity/md4c", "https://github.com/mity/md4c"),
    "giflib": ("giflib", None, "https://git.code.sf.net/p/giflib/code"),
    "jbig2dec": ("jbig2dec", "ArtifexSoftware/jbig2dec", "https://github.com/ArtifexSoftware/jbig2dec"),
    "lua": ("lua", "lua/lua", "https://github.com/lua/lua"),
}
ORIGINAL = ("giflib", "jbig2dec", "md4c", "mujs")   # the four projects the Phase 9 pre-registration names
RESERVE = ("lua",)                                  # added only when fewer than 10 pairs survive (D-039)

IN_CWES = frozenset({
    "CWE-78", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126",
    "CWE-127", "CWE-129", "CWE-131", "CWE-134", "CWE-190", "CWE-191", "CWE-193", "CWE-369",
    "CWE-606", "CWE-680", "CWE-787", "CWE-788", "CWE-789", "CWE-805", "CWE-806", "CWE-823",
})
OUT_CWES = frozenset({
    "CWE-400", "CWE-401", "CWE-415", "CWE-416", "CWE-457", "CWE-476", "CWE-617", "CWE-674",
    "CWE-704", "CWE-772", "CWE-835", "CWE-843", "CWE-908",
})
IN_WORDS = re.compile(
    r"buffer over(?:flow|-?read|run)|out[- ]of[- ]bounds|integer (?:overflow|underflow)|"
    r"divi(?:de|sion)[- ]by[- ]zero|format string|off[- ]by[- ]one",
    re.I,
)
OUT_WORDS = re.compile(
    r"use[- ]after[- ]free|double[- ]free|null pointer|memory leak|infinite loop|"
    r"recursion|stack exhaustion|assertion",
    re.I,
)
# "this vulnerability exists due to an incomplete fix for CVE-2016-7563"
INCOMPLETE_FIX = re.compile(r"incomplete fix for\s+(CVE-\d{4}-\d{4,7})", re.I)

COMMIT_REFS = (
    re.compile(r"github\.com/[^/\s]+/[^/\s]+/commit/([0-9a-f]{7,40})"),
    re.compile(r"codeberg\.org/[^/\s]+/[^/\s]+/commit/([0-9a-f]{7,40})"),
    re.compile(r"[;?&]h=([0-9a-f]{7,40})"),
    re.compile(r"/ci/([0-9a-f]{40})"),
    re.compile(r"findgit\.cgi\?([0-9a-f]{7,40})"),
)
GS_BUG = re.compile(r"bugs\.ghostscript\.com/show_bug\.cgi\?id=(\d+)")
GH_ISSUE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)/(?:issues|pull)/(\d+)")
SF_BUG = re.compile(r"sourceforge\.net/p/giflib/bugs/(\d+)")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}"
NVD_PAUSE_S = 7                     # NVD's unauthenticated rate limit
GH_EVENTS_URL = "https://api.github.com/repos/{}/issues/{}/events?per_page=100"
UA = "taintwalk-phase9-census"


class CensusError(RuntimeError):
    """The census cannot be computed exactly; no candidate list is written."""


# ---- snapshots ------------------------------------------------------------------------------

def _get(url: str, accept: str) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def fetch_nvd(out_dir: Path, projects: tuple[str, ...]) -> dict[str, Any]:
    """One NVD keyword query per project, hashed, so the decision pass is reproducible."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, name in enumerate(sorted(projects)):
        if i:
            time.sleep(NVD_PAUSE_S)
        raw = _get(NVD_URL.format(name), "application/json")
        (out_dir / f"{name}.json").write_bytes(raw)
        doc = json.loads(raw)
        if doc.get("totalResults", 0) > len(doc.get("vulnerabilities", [])):
            raise CensusError(f"{name}: NVD returned {len(doc.get('vulnerabilities', []))} of "
                              f"{doc.get('totalResults')} results; this census does not paginate")
        rows.append({"project": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "total_results": doc.get("totalResults"),
                     "vulnerabilities": len(doc.get("vulnerabilities", []))})
        print(f"[nvd] {name}: {rows[-1]['total_results']} results, "
              f"{rows[-1]['vulnerabilities']} returned")
    meta = {"fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "queries": rows}
    (out_dir / "fetch.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n",
                                       encoding="utf-8")
    return meta


def fetch_gh_events(repo: str, number: str, out_dir: Path) -> list[str]:
    """Commit ids that closed a GitHub issue, snapshotted to disk. [] when unavailable."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{repo.replace('/', '_')}_{number}.json"
    if not path.exists():
        try:
            raw = _get(GH_EVENTS_URL.format(repo, number), "application/vnd.github+json")
        except (urllib.error.HTTPError, OSError) as e:
            path.write_text(json.dumps({"error": str(e)}) + "\n", encoding="utf-8")
            print(f"[gh] {repo}#{number}: {e}")
            return []
        path.write_bytes(raw)
        time.sleep(1)
    doc = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict):
        return []
    return sorted({e["commit_id"] for e in doc
                   if e.get("event") == "closed" and e.get("commit_id")})


# ---- repositories ---------------------------------------------------------------------------

def _git(repo: Path, *args: str) -> tuple[int, str]:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       errors="replace")
    return r.returncode, r.stdout


class Repo:
    """One project's git history, read once. Commit messages are searched in memory."""

    def __init__(self, name: str, path: Path):
        if not (path / ".git").is_dir() and not (path / "HEAD").is_file():
            raise CensusError(f"{name}: no git repository at {path}; clone it first")
        self.name = name
        self.path = path
        rc, head = _git(path, "rev-parse", "HEAD")
        if rc != 0:
            raise CensusError(f"{name}: cannot read HEAD at {path}")
        self.head = head.strip()
        _, out = _git(path, "log", "--all", "--no-merges", "--format=%H%x00%B%x1e")
        self.msgs: dict[str, str] = {}
        for rec in out.split("\x1e"):
            rec = rec.strip()
            if rec:
                sha, _, body = rec.partition("\x00")
                self.msgs[sha.strip()] = body
        if not self.msgs:
            raise CensusError(f"{name}: no commits read from {path}")
        self._touches: dict[str, bool] = {}

    def full(self, sha: str) -> str | None:
        rc, out = _git(self.path, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}")
        return out.strip() if rc == 0 and out.strip() else None

    def touches_c(self, sha: str) -> bool:
        if sha not in self._touches:
            _, out = _git(self.path, "show", "--name-only", "--format=", sha)
            self._touches[sha] = any(l.strip().endswith(".c") for l in out.splitlines())
        return self._touches[sha]

    def grep(self, pattern: str) -> set[str]:
        rx = re.compile(pattern, re.I)
        return {s for s, body in self.msgs.items() if rx.search(body)}

    def info(self, sha: str) -> dict[str, Any]:
        """Facts the screens and the review need. Hunk functions are a preview only."""
        _, meta = _git(self.path, "log", "-1", "--format=%H%x00%cs%x00%s", sha)
        full, date, subject = (meta.strip().split("\x00") + ["", "", ""])[:3]
        _, parents = _git(self.path, "log", "-1", "--format=%P", sha)
        _, diff = _git(self.path, "show", "-U0", "--format=", sha, "--", "*.c")
        files: set[str] = set()
        funcs: set[str] = set()
        hunks = 0
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                files.add(line[6:])
            elif line.startswith("@@"):
                hunks += 1
                ctx = line.split("@@", 2)[-1].strip()
                m = re.search(r"([A-Za-z_]\w*)\s*\(", ctx)
                funcs.add(m.group(1) if m else (ctx[:40] or "?"))
        return {"commit": full, "parents": parents.split(), "date": date, "subject": subject,
                "c_files": sorted(files), "hunks": hunks, "hunk_funcs_preview": sorted(funcs)}


# ---- advisory reading -----------------------------------------------------------------------

def _english(cve: dict[str, Any]) -> str:
    return next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")


def _cwes(cve: dict[str, Any]) -> set[str]:
    return {d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])}


def project_match(cve: dict[str, Any], product: str, name: str, desc: str) -> str | None:
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4 and parts[4] == product:
                    return "cpe"
    return "text" if re.search(rf"\b{re.escape(name)}\b", desc, re.I) else None


def signal(cwes: set[str], text: str) -> tuple[str, str]:
    """One signal -> ("in" | "out" | "silent", evidence). Out wins over in within a signal."""
    out_hits = sorted(cwes & OUT_CWES) + ([m.group(0)] if (m := OUT_WORDS.search(text)) else [])
    in_hits = sorted(cwes & IN_CWES) + ([m.group(0)] if (m := IN_WORDS.search(text)) else [])
    if out_hits:
        return "out", out_hits[0]
    if in_hits:
        return "in", in_hits[0]
    return "silent", ""


def decide_scope(advisory: tuple[str, str], commit: tuple[str, str]) -> tuple[bool, str]:
    """In scope only if neither signal is out and at least one is in (pre-registered)."""
    a, b = advisory[0], commit[0]
    if a == "out":
        return False, f"advisory out of scope: {advisory[1]}"
    if b == "out":
        return False, f"fix commit out of scope: {commit[1]}"
    if a == "in" or b == "in":
        return True, f"advisory {a} ({advisory[1] or '-'}), commit {b} ({commit[1] or '-'})"
    return False, "no in-scope signal from either the advisory or the fix commit"


# ---- resolution -----------------------------------------------------------------------------

def bug_patterns(refs: list[str], gh: str | None) -> list[tuple[str, str]]:
    """(kind:number, commit-message regex) for bug/issue references belonging to this project."""
    out: list[tuple[str, str]] = []
    for u in refs:
        for m in GS_BUG.finditer(u):
            n = m.group(1)
            out.append((f"gs:{n}", rf"(?<!\d){n}(?!\d)" if len(n) >= 6
                        else rf"\bbug\s*#?\s*{n}(?!\d)"))
        for m in GH_ISSUE.finditer(u):
            if gh and f"{m.group(1)}/{m.group(2)}".lower() == gh.lower():
                n = m.group(3)
                out.append((f"gh:{n}", rf"(?:#|issues/|pull/){n}(?!\d)"))
        for m in SF_BUG.finditer(u):
            n = m.group(1)
            out.append((f"sf:{n}", rf"(?:sf|bug)[^\n]{{0,12}}#\s*{n}(?!\d)"))
    seen: set[str] = set()
    uniq: list[tuple[str, str]] = []
    for kind, pat in out:
        if kind not in seen:
            seen.add(kind)
            uniq.append((kind, pat))
    return uniq


def resolve(repo: Repo, cve_id: str, refs: list[str], gh: str | None,
            gh_dir: Path, fetch: bool) -> dict[str, Any]:
    """First of the four ordered sources that yields any commit touching a .c file."""
    nvd: set[str] = set()
    for u in refs:
        for rx in COMMIT_REFS:
            for m in rx.finditer(u):
                if (f := repo.full(m.group(1))):
                    nvd.add(f)
    bugs = bug_patterns(refs, gh)

    def closed_by() -> set[str]:
        found: set[str] = set()
        for kind, _ in bugs:
            if gh and kind.startswith("gh:") and (fetch or gh_dir.exists()):
                for s in fetch_gh_events(gh, kind[3:], gh_dir):
                    if (f := repo.full(s)):
                        found.add(f)
        return found

    def bug_grep() -> set[str]:
        found: set[str] = set()
        for _, pat in bugs:
            found |= repo.grep(pat)
        return found

    for source, fn in (("nvd_ref", lambda: nvd),
                       ("cve_grep", lambda: repo.grep(re.escape(cve_id))),
                       ("gh_closed", closed_by),
                       ("bug_grep", bug_grep)):
        commits = sorted(s for s in fn() if repo.touches_c(s))
        if commits:
            return {"source": source, "commits": commits, "bugs": [k for k, _ in bugs],
                    "resolution": "unique" if len(commits) == 1 else "ambiguous"}
    return {"source": None, "commits": [], "bugs": [k for k, _ in bugs], "resolution": "none"}


# ---- the census -----------------------------------------------------------------------------

def rows_for_project(name: str, repo: Repo, nvd_doc: dict[str, Any], gh_dir: Path,
                     fetch: bool) -> list[dict[str, Any]]:
    product, gh, _ = PROJECTS[name]
    rows: list[dict[str, Any]] = []
    for v in nvd_doc.get("vulnerabilities", []):
        cve = v["cve"]
        cid = cve["id"]
        desc = _english(cve)
        cwes = _cwes(cve)
        refs = [r.get("url", "") for r in cve.get("references", [])]
        row: dict[str, Any] = {
            "project": name, "cve": cid, "published": cve.get("published", "")[:10],
            "vuln_status": cve.get("vulnStatus", ""), "cwes": sorted(cwes), "description": desc,
            "kept": False, "exclusion": None,
        }
        if row["vuln_status"] == "Rejected":
            row["exclusion"] = "rejected CVE record"
            rows.append(row)
            continue
        if not (match := project_match(cve, product, name, desc)):
            row["exclusion"] = "other product"
            rows.append(row)
            continue
        row["project_match"] = match
        # D-037 S7 needs every matched CVE's fix commits, whatever its scope.
        s7 = resolve(repo, cid, refs, gh, gh_dir, fetch)
        row["s7_commits"] = s7["commits"]

        adv = signal(cwes, desc)
        row["advisory_signal"] = {"verdict": adv[0], "evidence": adv[1]}
        if adv[0] == "out":
            row["exclusion"] = f"advisory out of scope: {adv[1]}"
            rows.append(row)
            continue
        if (m := INCOMPLETE_FIX.search(desc)):
            row["exclusion"] = f"incomplete-fix follow-up of {m.group(1)}: its advisory cites the " \
                               "superseded bug, so the resolved commit is the insufficient one"
            row["supersedes"] = m.group(1)
            rows.append(row)
            continue

        res = s7                                # the same resolution, computed once
        row.update(res)
        if res["resolution"] != "unique":
            row["exclusion"] = f"fix commit {res['resolution']}"
            rows.append(row)
            continue
        sha = res["commits"][0]
        row["fix"] = repo.info(sha)
        cmt = signal(set(), row["fix"]["subject"])
        row["commit_signal"] = {"verdict": cmt[0], "evidence": cmt[1]}
        in_scope, why = decide_scope(adv, cmt)
        row["scope_reason"] = why
        if not in_scope:
            row["exclusion"] = why
            rows.append(row)
            continue
        if len(row["fix"]["parents"]) != 1:
            row["exclusion"] = f"fix commit has {len(row['fix']['parents'])} parents; a pair needs one"
            rows.append(row)
            continue
        row["pre_commit"] = row["fix"]["parents"][0]
        row["kept"] = True
        rows.append(row)
    rows.sort(key=lambda r: (r["cve"],))
    return rows


def collapse_and_cap(rows: list[dict[str, Any]]) -> None:
    """Shared fix commits collapse to the lowest CVE id; then cap per project with the seed."""
    by_commit: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if r["kept"]:
            by_commit.setdefault(r["fix"]["commit"], []).append(r)
    for sha, group in sorted(by_commit.items()):
        if len(group) > 1:
            group.sort(key=lambda r: r["cve"])
            keeper, rest = group[0], group[1:]
            keeper["aliases"] = [r["cve"] for r in rest]
            for r in rest:
                r["kept"] = False
                r["exclusion"] = f"same fix commit {sha[:12]} as {keeper['cve']} (one pair per change)"

    rng = random.Random(SEED)
    for name in sorted({r["project"] for r in rows}):
        kept = sorted((r for r in rows if r["project"] == name and r["kept"]),
                      key=lambda r: r["cve"])
        if len(kept) <= PER_PROJECT_CAP:
            continue
        drawn = set(rng.sample([r["cve"] for r in kept], PER_PROJECT_CAP))
        for r in kept:
            if r["cve"] not in drawn:
                r["kept"] = False
                r["exclusion"] = (f"not drawn: {len(kept)} candidates exceed the per-project cap of "
                                  f"{PER_PROJECT_CAP}, seed {SEED}")


def census(nvd_dir: Path, src_dir: Path, gh_dir: Path, fetch: bool,
           projects: tuple[str, ...] = ORIGINAL) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    repos: dict[str, Any] = {}
    for name in sorted(projects):
        path = nvd_dir / f"{name}.json"
        if not path.exists():
            raise CensusError(f"{path} is missing; run with --fetch first")
        repo = Repo(name, src_dir / name)
        repos[name] = {"path": str((src_dir / name).relative_to(REPO_ROOT)), "head": repo.head,
                       "commits": len(repo.msgs), "clone_url": PROJECTS[name][2]}
        rows += rows_for_project(name, repo, json.loads(path.read_text(encoding="utf-8")),
                                 gh_dir, fetch)
    collapse_and_cap(rows)
    rows.sort(key=lambda r: (r["project"], r["cve"]))
    kept = [r for r in rows if r["kept"]]
    return {
        "census_version": CENSUS_VERSION, "rules": "D-009",
        "seed": SEED, "per_project_cap": PER_PROJECT_CAP,
        "repositories": repos,
        "counts": {"rows": len(rows), "kept": len(kept),
                   "by_project": {n: sum(r["project"] == n for r in kept) for n in sorted(projects)}},
        "candidates": kept,
        "rows": rows,
    }


def report(doc: dict[str, Any]) -> int:
    print(f"\n{'project':<9} {'cve':<16} {'pub':<11} {'source':<10} {'fix':<11} {'commit':<10} "
          f"files hunks  preview")
    for r in doc["candidates"]:
        f = r["fix"]
        print(f"{r['project']:<9} {r['cve']:<16} {r['published']:<11} {r['source']:<10} "
              f"{f['date']:<11} {f['commit'][:10]} {len(f['c_files']):>5} {f['hunks']:>5}  "
              f"{'|'.join(f['hunk_funcs_preview'])[:46]}"
              + (f"  aliases {','.join(r['aliases'])}" if r.get("aliases") else ""))
    excl = Counter(r["exclusion"].split(":")[0] for r in doc["rows"] if not r["kept"])
    print(f"\nexclusions: " + ", ".join(f"{k} {v}" for k, v in sorted(excl.items())))
    for name, n in doc["counts"]["by_project"].items():
        print(f"[census] {name:<9} candidates {n}")
    total = doc["counts"]["kept"]
    print(f"[census] total candidates {total} (screens S1-S6 come next; the pairs that survive are "
          f"the corpus)")
    if total < MIN_PAIRS and set(doc["counts"]["by_project"]) <= set(ORIGINAL):
        print(f"[census] below {MIN_PAIRS}: the Lua reserve is pre-registered and must be added by ADR")
    print("CENSUS OK" if total else "CENSUS FAIL: no candidates")
    return 0 if total else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m taintwalk.corpus.real",
                               description="Phase 9 real-code corpus census (D-009).")
    p.add_argument("--out", default="runs/p9-census", help="where census.json and snapshots go")
    p.add_argument("--src", default="runs/p9-spike/src", help="dir holding one clone per project")
    p.add_argument("--fetch", action="store_true", help="snapshot NVD and GitHub events first")
    p.add_argument("--projects", default=",".join(ORIGINAL),
                   help="comma-separated projects (default: the four pre-registered ones; the reserve, "
                        "lua, is censused on its own, D-039)")
    a = p.parse_args(argv)
    projects = tuple(sorted({x.strip() for x in a.projects.split(",") if x.strip()}))
    unknown = [x for x in projects if x not in PROJECTS]
    if not projects or unknown:
        print(f"CENSUS FAIL: unknown projects {unknown or a.projects!r}")
        return 1

    out = Path(a.out) if Path(a.out).is_absolute() else REPO_ROOT / a.out
    src = Path(a.src) if Path(a.src).is_absolute() else REPO_ROOT / a.src
    nvd_dir, gh_dir = out / "nvd", out / "gh"
    try:
        if a.fetch:
            fetch_nvd(nvd_dir, projects)
        doc = census(nvd_dir, src, gh_dir, a.fetch, projects)
    except CensusError as e:
        print(f"CENSUS FAIL: {e}")
        return 1
    out.mkdir(parents=True, exist_ok=True)
    (out / "census.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                                     encoding="utf-8")
    rc = report(doc)
    print(f"census.json        : {out / 'census.json'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())