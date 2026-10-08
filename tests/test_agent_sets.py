"""Phase 10 (D-042): agent_sets builds dev/scored programs.txt lines that carry only paths and hex."""
import json
import re

import pytest

from taintwalk.eval.agent_sets import DEV_CASE_IDS, build_sets, root_addrs

ENTRY_FIELDS = {"cwe": "CWE-121", "flow_variant": "01", "stripped_sha256": "0" * 64}


def _fn(addr_hex, label, role):
    return {"addr_hex": addr_hex, "label": label, "role": role,
            "name": "x", "addr": 0, "cu": "t", "size": 1}


def _entry(case_id, funcs):
    return {"case_id": case_id, "functions": funcs, **ENTRY_FIELDS}


# A bad/entry root, two good/path roots, and three non-roots that must never reach a line
# (the good/entry dispatcher, a bad/sink hop, support code).
FUNCS = [
    _fn("0x1200", "good", "path"),
    _fn("0x1000", "bad", "entry"),
    _fn("0x1100", "good", "path"),
    _fn("0x1300", "good", "entry"),
    _fn("0x1400", "bad", "sink"),
    _fn("0x1500", "support", "support"),
]

FILLER = [_fn("0x2000", "bad", "entry"), _fn("0x2100", "good", "path")]


def _manifest(tmp_path, extra_entries=()):
    """A manifest holding all 13 dev cases (tw-0015 carrying FUNCS) plus any extra scored entries."""
    entries = [_entry(cid, FUNCS if cid == "tw-0015" else FILLER) for cid in DEV_CASE_IDS]
    entries.extend(extra_entries)
    path = tmp_path / "corpus-index.json"
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return path


def test_root_addrs_sorted_numerically_and_roots_only():
    assert root_addrs(_entry("tw-0015", FUNCS)) == ["0x1000", "0x1100", "0x1200"]


def test_split_and_line_format(tmp_path):
    manifest = _manifest(tmp_path, [_entry("tw-9001", [_fn("0x3000", "bad", "entry"),
                                                       _fn("0x3100", "good", "path")])])
    pdir = tmp_path / "programs"
    sets = build_sets(manifest_path=manifest, programs_dir=pdir)

    assert len(sets["dev"]) == 13
    assert sets["scored"] == [f"{pdir / 'tw-9001.json'} 0x3000,0x3100"]
    assert f"{pdir / 'tw-0015.json'} 0x1000,0x1100,0x1200" in sets["dev"]

    for line in sets["dev"] + sets["scored"]:
        path, addrs = line.split()
        assert path.endswith(".json")
        assert re.fullmatch(r"0x[0-9a-f]+(,0x[0-9a-f]+)*", addrs), addrs


def test_no_label_or_marker_leaks_into_lines(tmp_path):
    lines = build_sets(manifest_path=_manifest(tmp_path), programs_dir=tmp_path / "programs")
    text = "\n".join(lines["dev"] + lines["scored"])
    for token in ("bad", "good", "entry", "path", "sink", "support", "CWE"):
        assert token not in text


def test_missing_dev_case_fails_closed(tmp_path):
    path = tmp_path / "corpus-index.json"
    path.write_text(json.dumps({"entries": [_entry("tw-0015", FUNCS)]}), encoding="utf-8")
    with pytest.raises(ValueError):
        build_sets(manifest_path=path, programs_dir=tmp_path)


def test_dev_slice_is_thirteen_distinct():
    assert len(DEV_CASE_IDS) == len(set(DEV_CASE_IDS)) == 13
