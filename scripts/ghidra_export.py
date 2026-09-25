#!/usr/bin/env python3
"""Export one stripped ELF to program.json via PyGhidra headless.

Runs as its own process: a JVM can start only once per process (D-012), and one
process per binary also isolates crashes and lets the caller enforce a wall timeout.
Invoked by taintwalk.extract.ghidra_runner; runnable by hand for debugging.

usage: python scripts/ghidra_export.py <input.elf> <output.json> --project-dir DIR
                                       [--decompile-timeout 60]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

try:
    from taintwalk.config import ghidra_install_dir, load_config
except ModuleNotFoundError:  # running from a checkout without an install
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from taintwalk.config import ghidra_install_dir, load_config

from taintwalk.extract.ghidra_runner import exporter_fingerprint
from taintwalk.extract.schema import (
    SCHEMA_VERSION,
    BinaryRef,
    CalleeRef,
    Function,
    Program,
    Provenance,
)

# Ghidra's ELF loader places import stubs in a synthetic "EXTERNAL" memory block as
# thunk functions whose isExternal() is False. Classify them by block instead.
EXTERNAL_BLOCK = "EXTERNAL"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect(program, decompile_timeout: int, plt_blocks: set[str], text_blocks: set[str]):
    """Walk the program once and build raw rows; then scope, then decompile."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    mon = TaskMonitor.DUMMY
    mem = program.getMemory()
    listing = program.getListing()
    base = int(program.getImageBase().getOffset())

    def off(addr) -> str:
        return hex(int(addr.getOffset()) - base)

    def raw(addr) -> str:
        return hex(int(addr.getOffset()))

    def block_of(addr) -> str:
        b = mem.getBlock(addr)
        return str(b.getName()) if b is not None else "?"

    def ptr_array(name: str) -> list[int]:
        b = mem.getBlock(name)
        if b is None:
            return []
        return [
            int(mem.getLong(b.getStart().add(i * 8))) & 0xFFFFFFFFFFFFFFFF
            for i in range(int(b.getSize()) // 8)
        ]

    def resolve(c) -> CalleeRef:
        """Follow .plt.sec / .plt.got thunks to the thing actually being called."""
        if c.isExternal():
            return CalleeRef(kind="external", name=str(c.getName()))
        if c.isThunk():
            t = c.getThunkedFunction(True)
            if t is not None:
                if t.isExternal():
                    return CalleeRef(
                        kind="external", name=str(t.getName()), via_thunk=off(c.getEntryPoint())
                    )
                return CalleeRef(
                    kind="internal",
                    addr=off(t.getEntryPoint()),
                    via_thunk=off(c.getEntryPoint()),
                )
        return CalleeRef(kind="internal", addr=off(c.getEntryPoint()))

    rows: list[dict] = []
    for f in program.getFunctionManager().getFunctions(True):
        ep = f.getEntryPoint()
        thunk_target = None
        if f.isThunk():
            t = f.getThunkedFunction(True)
            if t is not None:
                thunk_target = str(t.getName())

        callees = [resolve(c) for c in f.getCalledFunctions(mon)]
        callees.sort(key=lambda r: (r.kind, r.addr or "", r.name or ""))

        callers = sorted(
            (off(c.getEntryPoint()) for c in f.getCallingFunctions(mon) if not c.isExternal()),
            key=lambda x: int(x, 16),
        )

        indirect = 0
        if not f.isExternal():
            for ins in listing.getInstructions(f.getBody(), True):
                ft = ins.getFlowType()
                if ft.isCall() and ft.isComputed():
                    indirect += 1

        rows.append(
            {
                "addr": off(ep),
                "ghidra_addr": raw(ep),
                "ghidra_name": str(f.getName()),
                "size": int(f.getBody().getNumAddresses()),
                "block": block_of(ep),
                "is_thunk": bool(f.isThunk()),
                "is_external": bool(f.isExternal()),
                "thunk_target": thunk_target,
                "callees": callees,
                "callers": callers,
                "indirect_call_sites": indirect,
                "_f": f,
            }
        )

    # --- CRT detection, label-free (D-015 A) -------------------------------
    # Seed: the ELF entry point inside .text, plus every .init_array/.fini_array
    # target. Close over "every caller of this function is already CRT". Functions
    # with no callers are never absorbed, which is what keeps main() (reached only
    # as a pointer handed to __libc_start_main) out of the CRT set.
    by_addr = {r["addr"]: r for r in rows}
    entry_points = {
        off(a) for a in program.getSymbolTable().getExternalEntryPointIterator()
    }

    def norm(v: int) -> str:
        return hex(v - base) if v >= base else hex(v)

    crt: set[str] = {
        a for a in entry_points if a in by_addr and by_addr[a]["block"] in text_blocks
    }
    for v in ptr_array(".init_array") + ptr_array(".fini_array"):
        n = norm(v)
        if n in by_addr:
            crt.add(n)

    changed = True
    while changed:
        changed = False
        for r in rows:
            if r["addr"] in crt or r["block"] not in text_blocks or not r["callers"]:
                continue
            if all(c in crt for c in r["callers"]):
                crt.add(r["addr"])
                changed = True

    # --- scope ------------------------------------------------------------
    # Order matters. CRT is checked before thunk because frame_dummy can be a
    # thunk (a lone `jmp register_tm_clones`) and must still count as CRT.
    for r in rows:
        reason = None
        if r["is_external"] or r["block"] == EXTERNAL_BLOCK:
            reason = "external"
        elif r["block"] in plt_blocks:
            reason = "plt"
        elif r["block"] not in text_blocks:
            reason = "non_text"
        elif r["addr"] in crt:
            reason = "crt"
        elif r["is_thunk"]:
            reason = "thunk"
        r["excluded_reason"] = reason
        r["in_scope"] = reason is None

    # --- decompile in-scope functions only --------------------------------
    dec = DecompInterface()
    dec.openProgram(program)
    t_dec = 0.0
    try:
        for r in rows:
            if not r["in_scope"]:
                continue
            t0 = time.perf_counter()
            res = dec.decompileFunction(r["_f"], decompile_timeout, mon)
            t_dec += time.perf_counter() - t0
            if res.decompileCompleted():
                r["pseudo_c"] = str(res.getDecompiledFunction().getC())
                r["decompile_failed"] = False
                r["decompile_error"] = None
            else:
                r["pseudo_c"] = None
                r["decompile_failed"] = True
                msg = res.getErrorMessage()
                r["decompile_error"] = str(msg) if msg else "decompileCompleted() == False"
    finally:
        dec.dispose()

    functions = [
        Function(**{k: v for k, v in r.items() if not k.startswith("_")}) for r in rows
    ]
    functions.sort(key=lambda f: int(f.addr, 16))

    text = mem.getBlock(".text")
    meta = {
        "image_base": hex(base),
        "text_addr": off(text.getStart()) if text is not None else "0x0",
        "text_size": int(text.getSize()) if text is not None else 0,
        "decompile_seconds": round(t_dec, 3),
    }
    return functions, meta


def export(target: Path, out: Path, project_dir: Path, decompile_timeout: int) -> int:
    cfg = load_config()
    ecfg = cfg.get("extract", {})
    os.environ["GHIDRA_INSTALL_DIR"] = str(ghidra_install_dir(cfg))

    import pyghidra

    pyghidra.start()

    from ghidra.framework import Application

    project_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    with warnings.catch_warnings():
        # open_program() is deprecated in pyghidra 3.1 in favour of open_project() +
        # program_context(). It works, and D-010 pins Ghidra 12.1.4, so the
        # deprecation cannot change under us. Documented in D-015.
        warnings.simplefilter("ignore", DeprecationWarning)
        with pyghidra.open_program(
            str(target),
            project_location=str(project_dir),
            project_name="tw-extract",
            analyze=True,
        ) as flat_api:
            t_analyze = time.perf_counter() - t0
            program = flat_api.getCurrentProgram()
            functions, meta = _collect(
                program,
                decompile_timeout,
                set(ecfg.get("plt_blocks", [".plt", ".plt.sec", ".plt.got"])),
                set(ecfg.get("text_blocks", [".text"])),
            )
            ghidra_version = str(Application.getApplicationVersion())

    prog = Program(
        provenance=Provenance(
            schema_version=SCHEMA_VERSION,
            exporter_sha256=exporter_fingerprint(),
            generated_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ghidra_version=ghidra_version,
            pyghidra_version=str(getattr(pyghidra, "__version__", "unknown")),
            python_version=platform.python_version(),
            decompile_timeout_s=decompile_timeout,
            analyze_seconds=round(t_analyze, 3),
            decompile_seconds=meta["decompile_seconds"],
        ),
        binary=BinaryRef(
            path=str(target),
            sha256=sha256_file(target),
            image_base=meta["image_base"],
            text_addr=meta["text_addr"],
            text_size=meta["text_size"],
        ),
        functions=functions,
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(prog.model_dump_json(indent=2) + "\n", encoding="utf-8")

    # Read back through the schema: a file this process cannot re-load is a bug here,
    # not something for the report to discover later.
    Program.model_validate_json(out.read_text(encoding="utf-8"))

    c = prog.counts
    print(
        f"{target.name}: {c['total']} functions, {c['in_scope']} in scope "
        f"(thunk {c['thunk']}, plt {c['plt']}, ext {c['external']}, crt {c['crt']}, "
        f"non_text {c['non_text']}), decompile_failed {c['decompile_failed']}, "
        f"analyze {prog.provenance.analyze_seconds}s"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Export one stripped ELF to program.json")
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--decompile-timeout", type=int, default=60)
    args = ap.parse_args()

    target = Path(args.input).resolve()
    if not target.is_file():
        print(f"no such file: {target}", file=sys.stderr)
        return 1
    return export(
        target, Path(args.output), Path(args.project_dir), args.decompile_timeout
    )


if __name__ == "__main__":
    sys.exit(main())