"""Phase 7 scorer shakedown sample (D-028). Eval side. The real-corpus tests fail, never
skip, when runs/p2-extract or the manifest is missing (checks fail closed)."""
from __future__ import annotations

import json
import random

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.eval.sample import SHAKEDOWN_SEED, select_binaries, write_shakedown
from taintwalk.extract.report import load_manifest

FLOWS = ("01", "31", "41", "42", "44", "45", "52", "54", "63")
PROGRAMS = REPO_ROOT / "runs/p2-extract/programs"


def _fake_manifest() -> dict:
    entries, n = [], 0
    for f in FLOWS:
        for stratum, k in (("external", 4), ("fixed_sink", 2)):
            for _ in range(k):
                n += 1
                entries.append({"case_id": f"tw-{n:04d}", "stripped_sha256": f"{n:064x}",
                                "cwe": "CWE-121", "flow_variant": f, "stratum": stratum})
    return {"entries": entries}


def _shape(rows: list[dict]) -> tuple[list[str], list[str]]:
    ext = [r["flow_variant"] for r in rows if r["stratum"] == "external"]
    fix = [r["flow_variant"] for r in rows if r["stratum"] == "fixed_sink"]
    return ext, fix


def test_select_is_seeded_and_stratified():
    m = _fake_manifest()
    rows = select_binaries(m)
    ext, fix = _shape(rows)
    assert sorted(ext) == list(FLOWS)
    assert len(fix) == 3 and len(set(fix)) == 3
    assert select_binaries(m) == rows
    assert len({tuple(r["case_id"] for r in select_binaries(m, s)) for s in range(20)}) > 1


def test_select_ignores_manifest_order():
    m = _fake_manifest()
    shuffled = {"entries": list(m["entries"])}
    random.Random(1).shuffle(shuffled["entries"])
    assert select_binaries(shuffled) == select_binaries(m)


def test_select_fails_closed_on_an_empty_external_cell():
    m = _fake_manifest()
    m["entries"] = [e for e in m["entries"]
                    if not (e["flow_variant"] == "45" and e["stratum"] == "external")]
    with pytest.raises(ValueError, match="flow 45"):
        select_binaries(m)


def test_shakedown_on_the_real_corpus():
    rows = select_binaries(load_manifest())
    ext, fix = _shape(rows)
    assert sorted(ext) == list(FLOWS)
    assert len(fix) == 3 and len(set(fix)) == 3
    for r in rows:
        prog = json.loads((PROGRAMS / f"{r['case_id']}.json").read_text(encoding="utf-8"))
        assert prog["binary"]["sha256"] == r["sha256"], r["case_id"]


def test_write_shakedown_keeps_labels_out_of_programs_txt(tmp_path):
    rows = write_shakedown(tmp_path, load_manifest(), PROGRAMS)
    text = (tmp_path / "programs.txt").read_text(encoding="utf-8")
    assert text.splitlines() == [f"runs/p2-extract/programs/{r['case_id']}.json" for r in rows]
    assert "CWE" not in text
    key = json.loads((tmp_path / "eval" / "shakedown_key.json").read_text(encoding="utf-8"))
    assert key["seed"] == SHAKEDOWN_SEED and key["binaries"] == rows