"""Phase 5 runner (analysis/analyze_one.py) and sampler (eval/sample.py).

The runner is driven by a scripted in-process provider, so no model is needed. Real
programs are used because the leak gate's name layer needs a manifest sha (it fails closed
otherwise). Corpus-dependent tests fail, not skip, when runs/ is absent."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from taintwalk.analysis.analyze_one import (
    analysis_report,
    load_programs,
    load_sample,
    run_analyze,
    summary_path,
)
from taintwalk.analysis.prompts import SYSTEM, examples
from taintwalk.analysis.summary_schema import SummaryRecord
from taintwalk.eval.sample import FLOWS, select_sample
from taintwalk.llm.base import STOP_END, LLMProvider, RawResponse, Usage

REPO = Path(__file__).resolve().parents[1]
PROGRAMS = REPO / "runs/p2-extract/programs"
LABELS = REPO / "runs/p2-extract/labels"
VALID = examples()[1][2].model_dump_json()
INVALID = '{"params": []}'


class Scripted(LLMProvider):
    name = "scripted"

    def __init__(self, replies: list[str]) -> None:
        super().__init__("scripted-model", {}, cache=None)
        self.replies = list(replies)
        self.sent: list[str] = []

    def _send(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        self.sent.append(user)
        return RawResponse(text=self.replies.pop(0), stop_reason=STOP_END,
                           usage=Usage(input_tokens=100, output_tokens=50), model="scripted-model",
                           request_id=None, detail={"chars_per_token": 3.0})


@pytest.fixture(scope="module")
def tw0001() -> tuple[str, dict[str, Any], str]:
    p = PROGRAMS / "tw-0001.json"
    assert p.exists(), f"{p} missing; run `taintwalk extract --all --report` first"
    prog = json.loads(p.read_text())
    fn = next(f for f in prog["functions"] if f["in_scope"])
    return prog["binary"]["sha256"], prog, fn["addr"]


def _run(tw0001, replies, tmp_path):
    sha, prog, addr = tw0001
    prov = Scripted(replies)
    rows = run_analyze(prov, [(sha, addr)], {sha: prog}, tmp_path)
    return prov, rows[0]


# ---- runner -----------------------------------------------------------------------------

def test_single_function_end_to_end(tw0001, tmp_path):
    sha, _, addr = tw0001
    prov, row = _run(tw0001, [VALID], tmp_path)
    assert row["status"] == "ok" and not row["repaired"] and row["attempts"] == 1
    rec = SummaryRecord.model_validate(row["record"])
    assert rec.address == addr and rec.function == row["function"]
    on_disk = json.loads(summary_path(tmp_path, sha, addr).read_text())
    assert on_disk == row
    assert (tmp_path / "system.txt").read_text() == SYSTEM
    prompts = json.loads(next((tmp_path / "prompts").glob("*.json")).read_text())
    assert prompts["user"] == prov.sent[0] and prompts["attempts"][0]["text"] == VALID
    assert analysis_report([row], tmp_path) == 0
    assert json.loads((tmp_path / "analysis_report.json").read_text())["schema_valid"] == 1


def test_repair_is_recorded(tw0001, tmp_path):
    prov, row = _run(tw0001, [INVALID, VALID], tmp_path)
    assert row["status"] == "ok" and row["repaired"] and row["attempts"] == 2
    assert len(prov.sent) == 2


def test_schema_failure_is_recorded_and_fails_the_gate(tw0001, tmp_path):
    _, row = _run(tw0001, [INVALID, INVALID], tmp_path)
    assert row["status"] == "failed" and row["failure"] == "schema" and row["record"] is None
    assert analysis_report([row], tmp_path) == 1


def test_unknown_function_is_rejected(tw0001, tmp_path):
    sha, prog, _ = tw0001
    with pytest.raises(ValueError, match="not an in-scope function"):
        run_analyze(Scripted([VALID]), [(sha, "0xdeadbeef")], {sha: prog}, tmp_path)


def test_sample_file_carries_only_sha_and_addr(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"functions": [{"sha256": "ab" * 32, "addr": "0x10"}]}))
    assert load_sample(ok) == [("ab" * 32, "0x10")]
    for doc in ({"functions": [{"sha256": "ab" * 32, "addr": "0x10", "label": "bad"}]},
                {"functions": [{"sha256": "ab" * 32, "addr": "0x10"}], "seed": 1},
                {"functions": []}):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(doc))
        with pytest.raises(ValueError):
            load_sample(bad)


def test_programs_index_by_sha():
    progs = load_programs(PROGRAMS)
    assert len(progs) == 240


# ---- sampler (eval side) ----------------------------------------------------------------

def test_sample_selection_rules():
    sample, key = select_sample(LABELS, 20, seed=20260927)
    assert len(sample) == 20 and all(set(s) == {"sha256", "addr"} for s in sample)
    assert Counter(k["label"] for k in key) == {"bad": 10, "good": 10}
    assert len({k["cwe"] for k in key}) == 13
    assert all(k["flow_variant"] in FLOWS for k in key)
    assert all(k["role"] == "entry" for k in key if k["label"] == "bad")
    assert all(k["role"] != "entry" for k in key if k["label"] == "good")
    assert [(k["sha256"], k["addr"]) for k in key] == [(s["sha256"], s["addr"]) for s in sample]
    assert select_sample(LABELS, 20, seed=20260927) == (sample, key)
    assert select_sample(LABELS, 20, seed=1)[0] != sample


def test_sample_exclusion_gives_a_disjoint_held_out_set():
    dev, _ = select_sample(LABELS, 20, seed=20260927)
    used = {(s["sha256"], s["addr"]) for s in dev}
    held, key = select_sample(LABELS, 20, seed=20260928, exclude=used)
    assert used.isdisjoint((s["sha256"], s["addr"]) for s in held)
    assert Counter(k["label"] for k in key) == {"bad": 10, "good": 10}