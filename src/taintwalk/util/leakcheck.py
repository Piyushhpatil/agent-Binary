"""Ground-truth leak gate -- Invariant I1.

Two layers, both applied to the COMPLETE text that would be sent to a model:

  static  label-shaped text that is never legitimate in a prompt: CWE ids, _bad/_good
          identifiers, bad()/good() call forms, G2B/B2G, Juliet support tokens, io.c.
          Needs no ground truth.
  name    a per-binary denylist built from the manifest: every bad/good/support function
          name and every source-file name/stem for that binary. `main` is allowed (every C
          program has one; it is not a label).

Contract (D-017):
  * assert_clean() raises LeakError. There is no warn mode, no environment variable, and
    no config key that disables it. Do not add one.
  * The name denylist never leaves this module. Callers learn one bit: clean, or LeakError.
  * A LeakError message is for the operator's terminal. It contains ground-truth names and
    must NEVER be fed back into a prompt (e.g. by the Phase 4 repair loop).
  * Phase 4 onward: every provider call passes its final prompt through assert_clean()
    before any network or cache I/O, so no code path reaches a model without it.
  * binary_sha256=None runs the static layer only -- an explicit choice for a binary with no
    manifest entry. A sha that IS given but is absent from the manifest raises
    LeakCheckConfigError: the name layer fails closed, it never silently skips.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

STATIC_PATTERNS: dict[str, re.Pattern[str]] = {
    "cwe_id":          re.compile(r"(?i)\bcwe[-_ ]?\d+"),
    "suffix_bad_good": re.compile(r"\w+_(?:bad|good)\w*"),
    "call_form":       re.compile(r"\b(?:bad|good)(?:G2B|B2G)?\d*\s*\("),
    "g2b_b2g":         re.compile(r"(?:G2B|B2G)\d*\b"),
    "juliet":          re.compile(r"(?i)\bjuliet\b"),
    "support_tokens":  re.compile(r"\b(?:std_testcase|testcasesupport|OMITGOOD|OMITBAD|INCLUDEMAIN)\b"),
    "io_c":            re.compile(r"\bio\.c\b"),
}

NAME_LABELS = frozenset({"bad", "good", "support"})
NAME_ALLOW = frozenset({"main"})


@dataclass(frozen=True)
class Finding:
    layer: str      # "static" | "name"
    pattern: str
    match: str
    context: str


class LeakError(RuntimeError):
    """A prompt contains ground-truth-derived text. The run must stop."""

    def __init__(self, findings: list[Finding]):
        self.findings = tuple(findings)
        lines = [f"GROUND-TRUTH LEAK: {len(self.findings)} finding(s) -- prompt rejected (I1)"]
        for f in self.findings[:10]:
            lines.append(f"  [{f.layer}:{f.pattern}] {f.match!r} in: {f.context}")
        if len(self.findings) > 10:
            lines.append(f"  ... {len(self.findings) - 10} more")
        super().__init__("\n".join(lines))


class LeakCheckConfigError(RuntimeError):
    """The name layer cannot be built (unknown binary, empty denylist). Fails closed."""


def _context(text: str, m: re.Match[str]) -> str:
    s = text.rfind("\n", 0, m.start()) + 1
    e = text.find("\n", m.end())
    return text[s: e if e != -1 else len(text)].strip()[:120]


def _default_manifest() -> str:
    from taintwalk.config import REPO_ROOT, load_config
    return str(REPO_ROOT / load_config()["corpus"]["manifest"])


@lru_cache(maxsize=4)
def _manifest_index(manifest_path: str) -> dict[str, dict]:
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    return {e["stripped_sha256"]: e for e in data["entries"]}


@lru_cache(maxsize=1024)
def _name_rx(binary_sha256: str, manifest_path: str) -> re.Pattern[str]:
    entry = _manifest_index(manifest_path).get(binary_sha256)
    if entry is None:
        raise LeakCheckConfigError(
            f"binary sha256 {binary_sha256[:12]}... is not in {manifest_path}; "
            "refusing to run the name layer blind")
    names = {f["name"] for f in entry["functions"] if f["label"] in NAME_LABELS}
    for s in entry["source_files"]:
        names.add(Path(s).stem)
        names.add(Path(s).name)
    names = {n for n in names if n} - NAME_ALLOW
    if not names:
        raise LeakCheckConfigError(f"{entry['case_id']}: empty name denylist")
    alt = "|".join(map(re.escape, sorted(names, key=len, reverse=True)))
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + alt + r")(?![A-Za-z0-9_])")


def scan(text: str, binary_sha256: str | None = None, *,
         manifest_path: str | Path | None = None) -> list[Finding]:
    if not isinstance(text, str):
        raise TypeError(f"leak scan needs str, got {type(text).__name__}")
    findings: list[Finding] = []
    for pname, rx in STATIC_PATTERNS.items():
        for m in rx.finditer(text):
            findings.append(Finding("static", pname, m.group(0), _context(text, m)))
    if binary_sha256 is not None:
        rx = _name_rx(binary_sha256, str(manifest_path or _default_manifest()))
        for m in rx.finditer(text):
            findings.append(Finding("name", "manifest", m.group(0), _context(text, m)))
    return findings


def assert_clean(text: str, binary_sha256: str | None = None, *,
                 manifest_path: str | Path | None = None) -> None:
    findings = scan(text, binary_sha256, manifest_path=manifest_path)
    if findings:
        raise LeakError(findings)