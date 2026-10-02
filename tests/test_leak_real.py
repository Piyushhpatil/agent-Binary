"""Phase 9 leak gate: CVE ids are a static pattern, and the name layer resolves a binary through the
Juliet manifest or the real-code manifest, failing closed when it is in neither or in both."""
from __future__ import annotations

import json

import pytest

from taintwalk.analysis.sanitize import PLACEHOLDER, redact_leaky_literals
from taintwalk.util import leakcheck
from taintwalk.util.leakcheck import LeakCheckConfigError, LeakError, assert_clean, scan

REAL_SHA = "ab" * 32
JULIET_SHA = "07510add94cd25f95eace56af1570d59265085e869cbf6bf4944aaf61cd2fac4"   # tw-0001


def real_manifest(tmp_path, name="real.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"entries": [{
        "case_id": "rw-0001", "stripped_sha256": REAL_SHA,
        "functions": [{"name": "js_strtod", "label": "bad"}],
        "source_files": ["jsdtoa.c"], "deny": ["CVE-2021-33797"]}]}), encoding="utf-8")
    return p


@pytest.mark.parametrize("text", ["fixed CVE-2021-33797 here", "cve_2016_9017", "Cve 2019 11411"])
def test_cve_ids_are_a_static_leak(text):
    with pytest.raises(LeakError):
        assert_clean(text)


def test_a_cve_literal_is_redacted_like_any_static_match():
    out, n = redact_leaky_literals('FUN_00101000("see CVE-2016-9017");')
    assert n == 1 and PLACEHOLDER in out


def test_name_layer_reads_a_real_manifest(tmp_path):
    mp = real_manifest(tmp_path)
    found = {f.match for f in scan("js_strtod jsdtoa jsdtoa.c CVE-2021-33797 strtod", REAL_SHA,
                                   manifest_path=mp) if f.layer == "name"}
    assert found == {"js_strtod", "jsdtoa", "jsdtoa.c", "CVE-2021-33797"}
    assert_clean("strtod(local_28, &local_30);", REAL_SHA, manifest_path=mp)


def test_default_manifests_add_the_real_one_when_configured(tmp_path, monkeypatch):
    mp = real_manifest(tmp_path)
    import taintwalk.config as cfg
    real_load = cfg.load_config

    def fake_load(path=None):
        c = real_load(path)
        c.setdefault("real", {})["manifest"] = str(mp)
        return c

    monkeypatch.setattr(cfg, "load_config", fake_load)
    paths = leakcheck._default_manifests()
    assert len(paths) == 2 and paths[1] == str(mp)
    with pytest.raises(LeakError):
        assert_clean("call js_strtod", REAL_SHA)
    assert_clean("int main(void) { return 0; }", JULIET_SHA)        # Juliet binaries still resolve
    with pytest.raises(LeakCheckConfigError, match="none of"):
        assert_clean("x", "cd" * 32)


def test_a_binary_in_two_manifests_fails_closed(tmp_path):
    a, b = real_manifest(tmp_path, "a.json"), real_manifest(tmp_path, "b.json")
    with pytest.raises(LeakCheckConfigError, match="manifests"):
        leakcheck._name_rx(REAL_SHA, (str(a), str(b)))


def test_an_unknown_binary_still_fails_closed_by_default():
    with pytest.raises(LeakCheckConfigError):
        assert_clean("x", "ef" * 32)