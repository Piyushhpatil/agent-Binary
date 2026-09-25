"""`taintwalk corpus verify`: mechanical proof of Invariants G1/G2 for every manifest entry.

Per entry:
  files    both binaries exist and still match the sha256 recorded in the manifest
  address  .text addr, size AND byte hash identical across unstripped, stripped, manifest (G2);
           every bad/good/harness function lies fully inside .text
  dwarf    the unstripped (labeled) binary has .symtab and .debug_info
  stray    the stripped (analyzed) binary has no .symtab/.strtab/.debug_*, and its .dynsym
           exposes no labeled or support function name
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from taintwalk.config import REPO_ROOT
from taintwalk.corpus.groundtruth import text_info
from taintwalk.corpus.select import corpus_cfg

NAME_CHECKED_LABELS = ("bad", "good", "harness", "support")
RANGE_CHECKED_LABELS = ("bad", "good", "harness")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inspect(path: Path) -> dict[str, Any]:
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        dyn = elf.get_section_by_name(".dynsym")
        return {"sections": {s.name for s in elf.iter_sections()},
                "text": text_info(elf),
                "dynsym": {s.name for s in dyn.iter_symbols()} if dyn else set()}


def verify_entry(e: dict[str, Any]) -> dict[str, list[str]]:
    probs: dict[str, list[str]] = {"files": [], "address": [], "dwarf": [], "stray": []}
    elf, st = REPO_ROOT / e["elf"], REPO_ROOT / e["stripped"]
    for p, key in ((elf, "elf_sha256"), (st, "stripped_sha256")):
        if not p.is_file():
            probs["files"].append(f"missing {e[key.replace('_sha256', '')]}")
        elif _sha256(p) != e[key]:
            probs["files"].append(f"sha256 changed since manifest: {p.name}")
    if not (elf.is_file() and st.is_file()):
        return probs

    u, s = _inspect(elf), _inspect(st)
    for field in ("addr", "size", "sha256"):
        vals = (u["text"][field], s["text"][field], e["text"][field])
        if len(set(vals)) != 1:
            probs["address"].append(f".text {field} differs: unstripped={vals[0]} "
                                    f"stripped={vals[1]} manifest={vals[2]}")
    lo, hi = e["text"]["addr"], e["text"]["addr"] + e["text"]["size"]
    for f in e["functions"]:
        if f["label"] in RANGE_CHECKED_LABELS and not (lo <= f["addr"] and f["addr"] + f["size"] <= hi):
            probs["address"].append(f"{f['name']} @{f['addr_hex']} not inside .text")

    for sec in (".symtab", ".debug_info"):
        if sec not in u["sections"]:
            probs["dwarf"].append(f"unstripped lacks {sec}")

    leftover = sorted(n for n in s["sections"]
                      if n in (".symtab", ".strtab") or n.startswith(".debug"))
    if leftover:
        probs["stray"].append(f"stripped still has {leftover}")
    named = {f["name"] for f in e["functions"] if f["label"] in NAME_CHECKED_LABELS}
    exposed = sorted(named & s["dynsym"])
    if exposed:
        probs["stray"].append(f"stripped .dynsym exposes {exposed[:5]}")
    return probs


def verify_corpus(manifest_path: str | Path | None = None) -> int:
    path = Path(manifest_path) if manifest_path else REPO_ROOT / corpus_cfg()["manifest"]
    m = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = m["entries"]
    per: Counter = Counter()
    failed: list[tuple[str, dict[str, list[str]]]] = []
    cwe_bytes = 0
    for e in entries:
        p = verify_entry(e)
        for k, v in p.items():
            if v:
                per[k] += 1
        if any(p.values()):
            failed.append((e["case_id"], p))
        elif b"CWE" in (REPO_ROOT / e["stripped"]).read_bytes():
            cwe_bytes += 1

    status = "OK" if entries and not failed else "FAIL"
    print(f"{status}: {len(entries) - len(failed)}/{len(entries)} entries, "
          f"{per['address']} address mismatches, {per['dwarf']} missing DWARF, "
          f"{per['stray']} stray symbols in stripped")
    print(f"  {per['files']} missing/altered files; G2 compares .text addr+size+sha256 3-way")
    print(f"  info: {cwe_bytes} stripped binaries contain the bytes 'CWE' (input for Phase 3 leak check)")
    for cid, p in failed[:20]:
        for kind, msgs in p.items():
            for msg in msgs:
                print(f"  {cid} [{kind}] {msg}")
    return 0 if status == "OK" else 1
