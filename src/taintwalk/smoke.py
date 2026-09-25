"""Phase 0 smoke test: compile -> strip a copy -> Ghidra headless -> print pseudo-C.

A miniature of the real pipeline: one compile (G1), a stripped copy whose
.text is proven identical (G2), and decompilation of the stripped copy only.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from taintwalk.config import REPO_ROOT, ghidra_install_dir, load_config

MARKER = "taintwalk smoke marker"

HELLO_C = f"""#include <stdio.h>

void greet(const char *who) {{
    printf("{MARKER}: %s\\n", who);
}}

int main(int argc, char **argv) {{
    greet(argc > 1 ? argv[1] : "world");
    return 0;
}}
"""


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc.stdout


def _sections(elf: Path) -> dict[str, tuple[int, int]]:
    """Map section name -> (address, size) from `readelf -SW`."""
    result: dict[str, tuple[int, int]] = {}
    for line in _run(["readelf", "-SW", str(elf)]).splitlines():
        line = line.strip()
        if not (line.startswith("[") and "]" in line):
            continue
        rest = line.split("]", 1)[1].split()
        # rest = [name, type, address, offset, size, ...]
        if len(rest) < 5:
            continue
        try:
            result[rest[0]] = (int(rest[2], 16), int(rest[4], 16))
        except ValueError:
            continue  # header row
    return result


def _decompile_marker_functions(stripped: Path, proj_dir: Path) -> list[tuple[str, str, str]]:
    """Open the stripped ELF headless, auto-analyze, decompile functions that reference MARKER."""
    import pyghidra  # imported late: JVM starts on first use

    found: list[tuple[str, str, str]] = []
    with pyghidra.open_program(
        str(stripped), project_location=str(proj_dir), project_name="p0smoke", analyze=True
    ) as flat_api:
        # Java imports only work after the JVM is running.
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        program = flat_api.getCurrentProgram()
        ifc = DecompInterface()
        ifc.openProgram(program)
        monitor = ConsoleTaskMonitor()
        try:
            for func in program.getFunctionManager().getFunctions(True):
                if func.isThunk() or func.isExternal():
                    continue
                res = ifc.decompileFunction(func, 60, monitor)
                if not res.decompileCompleted():
                    continue
                code = str(res.getDecompiledFunction().getC())
                if "taintwalk" in code:
                    found.append((str(func.getName()), str(func.getEntryPoint()), code))
        finally:
            ifc.dispose()
    return found


def run_smoke() -> int:
    cfg = load_config()
    os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_install_dir(cfg))

    out = REPO_ROOT / cfg["smoke"]["out_dir"]
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    src = out / "hello.c"
    elf = out / "hello.elf"
    stripped = out / "hello.stripped.elf"
    src.write_text(HELLO_C, encoding="utf-8")

    # [1] One compile, never two (Invariant G1).
    _run(["gcc", *cfg["smoke"]["cflags"], str(src), "-o", str(elf)])
    print(f"[1/4] compiled      {elf.relative_to(REPO_ROOT)}  ({' '.join(cfg['smoke']['cflags'])})")

    # [2] Strip a COPY, then prove the copy is the same code (Invariant G2, in miniature).
    shutil.copy2(elf, stripped)
    _run(["strip", str(stripped)])
    full, strp = _sections(elf), _sections(stripped)
    problems = []
    for name in (".symtab", ".debug_info"):
        if name not in full:
            problems.append(f"unstripped ELF is missing {name}")
        if name in strp:
            problems.append(f"stripped ELF still contains {name}")
    if ".text" not in full or full.get(".text") != strp.get(".text"):
        problems.append(f".text differs: {full.get('.text')} vs {strp.get('.text')}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    addr, size = full[".text"]
    print(f"[2/4] strip-a-copy  .symtab/.debug_info removed; .text identical @0x{addr:x} size 0x{size:x}")

    # [3] Ghidra headless on the stripped copy ONLY.
    print("[3/4] Ghidra headless analysis of the stripped copy (first run ~30-90 s) ...", flush=True)
    found = _decompile_marker_functions(stripped, out / "ghidra_proj")
    if not found:
        print("FAIL: no decompiled function references the marker string")
        return 1

    # [4] Show it.
    print(f"[4/4] decompiled {len(found)} function(s) referencing the marker:\n")
    for name, entry, code in found:
        print(f"// {name} @ {entry}")
        print(code.strip())
        print()
    print("SMOKE OK")
    return 0
