"""`taintwalk doctor`: verify every Phase 0 dependency and print a table.

Exit code 0 only if every row is OK. A doctor that cannot fail is useless,
so each check asserts a specific version or property, not mere presence.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from taintwalk.config import REPO_ROOT, ghidra_install_dir, load_config

Check = tuple[str, bool, str]

_PYGHIDRA_PROBE = (
    "import pyghidra; pyghidra.start(); "
    "from ghidra.framework import Application; "
    "print('PYGHIDRA_VERSION=' + str(Application.getApplicationVersion()))"
)


def _check_repo_location() -> Check:
    path = str(REPO_ROOT)
    ok = not path.startswith("/mnt/")
    detail = path if ok else f"{path} is on the Windows filesystem (violates D-004)"
    return ("repo-location", ok, detail)


def _check_python(cfg: dict[str, Any]) -> Check:
    want = tuple(int(x) for x in str(cfg["toolchain"]["min_python"]).split("."))
    have = sys.version_info[:2]
    return ("python", have >= want, f"{sys.version.split()[0]} ({sys.executable}), need >= {cfg['toolchain']['min_python']}")


def _check_tool(name: str) -> Check:
    path = shutil.which(name)
    if path is None:
        return (name, False, "not found on PATH")
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (name, False, f"failed to run: {exc}")
    lines = (proc.stdout or proc.stderr).strip().splitlines()
    return (name, proc.returncode == 0, lines[0] if lines else "(no version output)")


def _check_java(cfg: dict[str, Any]) -> Check:
    want = int(cfg["toolchain"]["java_major"])
    path = shutil.which("java")
    if path is None:
        return ("java", False, "not found on PATH")
    try:
        proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ("java", False, f"failed to run: {exc}")
    text = (proc.stderr or proc.stdout).strip()
    first = text.splitlines()[0] if text else ""
    match = re.search(r'version "(\d+)', text)
    if not match:
        return ("java", False, f"could not parse version from: {first}")
    major = int(match.group(1))
    return ("java", major == want, f"{first} (need major {want})")


def _check_ghidra(cfg: dict[str, Any], gdir: Path) -> Check:
    want = str(cfg["ghidra"]["expected_version"])
    props = gdir / "Ghidra" / "application.properties"
    if not props.is_file():
        return ("ghidra", False, f"no install at {gdir}")
    version = None
    for line in props.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.version="):
            version = line.split("=", 1)[1].strip()
            break
    return ("ghidra", version == want, f"{version} at {gdir} (expected {want})")


def _check_pyghidra(cfg: dict[str, Any], gdir: Path) -> Check:
    # Run in a subprocess: a JVM can only be started once per process, and a
    # failing JVM start should not take the doctor down with it.
    want = str(cfg["ghidra"]["expected_version"])
    env = dict(os.environ, GHIDRA_INSTALL_DIR=str(gdir))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _PYGHIDRA_PROBE],
            capture_output=True, text=True, timeout=180, env=env,
        )
    except subprocess.TimeoutExpired:
        return ("pyghidra", False, "JVM start timed out after 180 s")
    match = re.search(r"PYGHIDRA_VERSION=(\S+)", proc.stdout)
    if proc.returncode != 0 or not match:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        return ("pyghidra", False, tail[-1] if tail else f"exit code {proc.returncode}")
    got = match.group(1)
    return ("pyghidra", got == want, f"JVM started via JPype, Ghidra {got}")


def run_doctor() -> int:
    cfg = load_config()
    gdir = ghidra_install_dir(cfg)

    checks: list[Callable[[], Check]] = [
        _check_repo_location,
        lambda: _check_python(cfg),
        lambda: _check_tool("gcc"),
        lambda: _check_tool("objdump"),
        lambda: _check_tool("strip"),
        lambda: _check_tool("readelf"),
        lambda: _check_java(cfg),
        lambda: _check_ghidra(cfg, gdir),
        lambda: _check_pyghidra(cfg, gdir),
    ]

    print(f"{'CHECK':<14} {'STATUS':<6} DETAIL")
    failed = 0
    for check in checks:
        name, ok, detail = check()
        failed += 0 if ok else 1
        print(f"{name:<14} {'OK' if ok else 'FAIL':<6} {detail}", flush=True)

    print()
    print("ALL OK" if failed == 0 else f"{failed} check(s) FAILED")
    return 0 if failed == 0 else 1
