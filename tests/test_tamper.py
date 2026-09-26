"""Negative tests for `taintwalk corpus verify` (Invariants G1/G2).

Promoted from runs/p1-tamper/tamper.py. Each test writes a one-entry manifest,
tampers with it, and asserts verify's exit code.

These tests need the built corpus. If it is absent they FAIL rather than skip:
a skipped check reads as green, and checks in this project fail closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.corpus.verify import verify_corpus

# Relative to REPO_ROOT, like the original script, so manifest paths resolve
# exactly as they did when tamper.py was proven. runs/ is gitignored.
WORK = Path("runs/p3-tests/tamper")


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def ctx():
    old = Path.cwd()
    os.chdir(REPO_ROOT)
    try:
        man_path = Path("corpus/manifest.json")
        assert man_path.is_file(), "corpus/manifest.json missing"
        m = json.loads(man_path.read_text(encoding="utf-8"))
        assert m["entries"], "manifest has no entries"
        e = m["entries"][0]
        for key in ("elf", "stripped"):
            p = Path(e[key])
            assert p.is_file() and p.stat().st_size > 0, (
                f"{p} missing or empty; run `taintwalk corpus build` first"
            )
        if WORK.exists():
            shutil.rmtree(WORK)
        WORK.mkdir(parents=True)
        yield m, e
    finally:
        os.chdir(old)


def _one_entry(m: dict, e: dict, name: str, **override) -> Path:
    t = json.loads(json.dumps(m))
    t["entries"] = [dict(e, **override)]
    p = WORK / f"{name}.json"
    p.write_text(json.dumps(t), encoding="utf-8")
    return p


def test_control_passes(ctx):
    m, e = ctx
    assert verify_corpus(_one_entry(m, e, "control")) == 0


def test_recompile_at_O1_is_caught(ctx):
    """A second compile (G1 violation) must fail the 3-way .text check."""
    m, e = ctx
    cflags = m["toolchain"]["cflags"]
    assert "-O0" in cflags, "expected -O0 in manifest cflags; the tamper would be a no-op"
    flags = ["-O1" if f == "-O0" else f for f in cflags]

    root = Path(m["juliet"]["root"])
    sup = root / "testcasesupport"
    out = WORK / "A_recompiled_O1.elf"
    subprocess.run(
        ["gcc", *flags, f"-I{sup}", str(sup / "io.c"),
         *[str(root / f) for f in e["source_files"]], "-o", str(out)],
        check=True,
    )
    assert _sha(out) != e["elf_sha256"], "recompile produced an identical binary; tamper is void"
    rc = verify_corpus(_one_entry(m, e, "A", elf=out.as_posix(), elf_sha256=_sha(out)))
    assert rc == 1


def test_never_stripped_copy_is_caught(ctx):
    """A 'stripped' file that still carries symbols must fail as stray sections."""
    m, e = ctx
    out = WORK / "B_never_stripped.elf"
    shutil.copy2(e["elf"], out)
    rc = verify_corpus(_one_entry(m, e, "B", stripped=out.as_posix(), stripped_sha256=_sha(out)))
    assert rc == 1