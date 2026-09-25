"""Ground truth from the UNSTRIPPED ELF, and the corpus manifest (Phase 1, D-005, D-013).

Labels come from provenance first, names second:
  1. Known CRT symbols (_start, frame_dummy, ...) -> `crt`.
  2. Defining compile unit from DWARF (DW_TAG_compile_unit / DW_AT_name).
     A support-source CU (io.c) -> `support`. This is what keeps io.c's empty
     bad1()..bad9() / good1()..good9() stubs from becoming labels.
  3. In a test-case CU (CWE*.c): `main` -> harness; name tail starting with
     bad/good -> bad/good with a role (entry/source/sink/path).
  4. Anything else, including a function with no DWARF -> `unknown` (fails loudly).
Every bad/good/harness function's symtab range must equal its DWARF range.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

from elftools.elf.elffile import ELFFile

from taintwalk.config import REPO_ROOT
from taintwalk.corpus.select import corpus_cfg

JULIET_VERSION = "1.3"
JULIET_ZIP_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
MANIFEST_SCHEMA = 1
CRT_FUNCS = frozenset({"_start", "_init", "_fini", "deregister_tm_clones", "register_tm_clones",
                       "__do_global_dtors_aux", "frame_dummy", "_dl_relocate_static_pie",
                       "__libc_csu_init", "__libc_csu_fini"})
# CWE121_Stack_Based_Buffer_Overflow__CWE131_memcpy_52b_badSink -> tail "badSink"
PREFIXED = re.compile(r"^CWE\d+_.+?__.+_\d{2}[a-z]?_(\w+)$")
CONST_FORMS = frozenset({"DW_FORM_data1", "DW_FORM_data2", "DW_FORM_data4", "DW_FORM_data8",
                         "DW_FORM_udata", "DW_FORM_sdata", "DW_FORM_implicit_const"})


def text_info(elf: ELFFile) -> dict[str, Any]:
    sec = elf.get_section_by_name(".text")
    return {"addr": sec["sh_addr"], "size": sec["sh_size"],
            "sha256": hashlib.sha256(sec.data()).hexdigest()}


def text_info_path(path: Path) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return text_info(ELFFile(fh))


def dwarf_subprograms(elf: ELFFile) -> dict[int, dict[str, Any]]:
    """low_pc -> {name, lo, hi, cu}. Since DWARF 4, high_pc is usually a LENGTH
    (constant form), not an address; both encodings are handled."""
    out: dict[int, dict[str, Any]] = {}
    if not elf.has_dwarf_info():
        return out
    for cu in elf.get_dwarf_info().iter_CUs():
        cu_attr = cu.get_top_DIE().attributes.get("DW_AT_name")
        cu_name = PurePosixPath(cu_attr.value.decode(errors="replace")).name if cu_attr else "?"
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                continue
            hp = die.attributes.get("DW_AT_high_pc")
            if hp is None:
                continue
            lo = die.attributes["DW_AT_low_pc"].value
            hi = lo + hp.value if hp.form in CONST_FORMS else hp.value
            nm = die.attributes.get("DW_AT_name")
            out[lo] = {"name": nm.value.decode(errors="replace") if nm else None,
                       "lo": lo, "hi": hi, "cu": cu_name}
    return out


def _classify(name: str, cu: str | None, support: set[str]) -> tuple[str, str | None]:
    if name in CRT_FUNCS:
        return "crt", None
    if cu is None:
        return "unknown", None
    if cu in support:
        return "support", None
    if not cu.startswith("CWE"):
        return "unknown", None
    if name == "main":
        return "harness", None
    m = PREFIXED.match(name)
    tail = m.group(1) if m else name
    if tail.startswith("bad"):
        label = "bad"
    elif tail.startswith("good"):
        label = "good"
    else:
        return "unknown", None
    if tail in ("bad", "good"):
        role = "entry"
    elif "Sink" in tail:
        role = "sink"
    elif "Source" in tail:
        role = "source"
    else:
        role = "path"
    return label, role


def extract_functions(path: Path, support: set[str]
                      ) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Every STT_FUNC in .text of the unstripped ELF, labeled.
    Returns (functions sorted by addr, symtab/DWARF mismatches, .text info)."""
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        tinfo = text_info(elf)
        lo_t, hi_t = tinfo["addr"], tinfo["addr"] + tinfo["size"]
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError(f"{path}: no .symtab -- ground truth must come from the unstripped ELF")
        dw = dwarf_subprograms(elf)
        funcs: list[dict[str, Any]] = []
        mism: list[str] = []
        seen: set[int] = set()
        for s in symtab.iter_symbols():
            if s["st_info"]["type"] != "STT_FUNC" or s["st_shndx"] == "SHN_UNDEF":
                continue
            addr, size = s["st_value"], s["st_size"]
            if not lo_t <= addr < hi_t or addr in seen:
                continue
            seen.add(addr)
            d = dw.get(addr)
            cu = d["cu"] if d else None
            label, role = _classify(s.name, cu, support)
            if label in ("bad", "good", "harness"):
                if d is None or d["hi"] - d["lo"] != size or d["name"] != s.name:
                    mism.append(f"{s.name}@{addr:#x}")
            funcs.append({"name": s.name, "addr": addr, "addr_hex": f"{addr:#x}", "size": size,
                          "label": label, "role": role, "cu": cu})
    funcs.sort(key=lambda f: f["addr"])
    return funcs, mism, tinfo


def write_manifest(c: dict[str, Any] | None = None) -> int:
    c = c or corpus_cfg()
    build_dir = REPO_ROOT / c["build_dir"]
    meta = json.loads((build_dir / "build.json").read_text(encoding="utf-8"))
    support = set(meta["support_sources"])
    control = {str(x) for x in c["control_flows"]}

    entries: list[dict[str, Any]] = []
    totals: Counter = Counter()
    problems: list[str] = []
    for b in meta["entries"]:
        funcs, mism, tinfo = extract_functions(REPO_ROOT / b["elf"], support)
        labels = Counter(f["label"] for f in funcs)
        totals.update(labels)
        unknown = [f["name"] for f in funcs if f["label"] == "unknown"]
        if unknown:
            problems.append(f"{b['case_id']}: unknown functions {unknown}")
        if mism:
            problems.append(f"{b['case_id']}: symtab/DWARF mismatch {mism}")
        if labels["harness"] != 1 or labels["bad"] < 1 or labels["good"] < 1:
            problems.append(f"{b['case_id']}: harness={labels['harness']} bad={labels['bad']} "
                            f"good={labels['good']}")
        entries.append({
            "case_id": b["case_id"], "cwe": f"CWE-{b['cwe']}",
            "functional_variant": b["functional"], "flow_variant": b["flow"],
            "is_control": b["flow"] in control, "stratum": b["stratum"],
            "source_kind": b["source_kind"], "sink_kind": b["sink_kind"],
            "substituted": b["substituted"], "source_files": b["files"],
            "elf": b["elf"], "stripped": b["stripped"],
            "elf_sha256": b["elf_sha256"], "stripped_sha256": b["stripped_sha256"],
            "text": tinfo, "functions": funcs,
        })

    print(f"labels: " + " ".join(f"{k}={totals[k]}" for k in
                                  ("bad", "good", "harness", "support", "crt", "unknown")))
    if problems:
        print(f"MANIFEST FAIL: {len(problems)} entries with problems (manifest NOT written):")
        for p in problems[:20]:
            print("  " + p)
        return 1

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "juliet": {"suite": "Juliet C/C++", "version": JULIET_VERSION,
                   "zip_sha256": JULIET_ZIP_SHA256, "root": meta["juliet_root"]},
        "toolchain": {"gcc": meta["gcc"], "strip": meta["strip"],
                      "cflags": meta["cflags"], "support_sources": meta["support_sources"]},
        "selection": {"seed": meta["seed"], "digest": meta["selection_digest"],
                      "attempts": meta["attempts"], "failures": meta["failures"],
                      "build_log": f"{c['build_dir']}/build_log.jsonl"},
        "label_rules": "crt list; DWARF CU io.c -> support; test-case CU: main -> harness, "
                       "tail bad*/good* -> bad/good (role entry/source/sink/path); else unknown",
        "entries": entries,
    }
    out = REPO_ROOT / c["manifest"]
    out.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"MANIFEST: {len(entries)} entries, {len({e['cwe'] for e in entries})} CWEs, "
          f"{len({e['flow_variant'] for e in entries})} flows; wrote {c['manifest']}")
    return 0
