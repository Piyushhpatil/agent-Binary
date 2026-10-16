"""Cost from cache entries (Phase 8, D-032): per-arm keys, dedupe, live spend, cache writes, dollars."""
from __future__ import annotations

import json

import pytest

from taintwalk.config import REPO_ROOT
from taintwalk.eval.cost import CostError, cache_entry, cost_report, dollars, usage_of

P6 = REPO_ROOT / "runs" / "p6-gate"
SHA = "ab" * 32
K1, K2, K3, K4 = "1" * 64, "2" * 64, "3" * 64, "4" * 64


def _usage(inp, out, cached=0):
    return {"input_tokens": inp, "output_tokens": out, "thinking_tokens": 0,
            "provider_cached_input_tokens": cached}


def _entry(cache, key, inp, out):
    p = cache / key[:2] / f"{key}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"key": key, "identity": {"provider": "anthropic", "model": "claude-sonnet-5-5"},
                             "usage": _usage(inp, out)}), encoding="utf-8")


def _run(tmp_path):
    d = tmp_path / "run"
    (d / "summaries").mkdir(parents=True)
    (d / "baseline" / "summaries").mkdir(parents=True)
    walk = {"binary_sha256": SHA,
            "functions": {"0x10": {"context_chars": 0}, "0x20": {"context_chars": 50}},
            "baseline": {"0x20": {"status": "ok", "failure": None, "cache_hit": False}}}
    (d / "walk.json").write_text(json.dumps(walk), encoding="utf-8")
    for a, k in (("0x10", K1), ("0x20", K2)):
        (d / "summaries" / f"{SHA[:12]}_{a}.json").write_text(json.dumps({"cache_key": k}), encoding="utf-8")
    (d / "baseline" / "summaries" / f"{SHA[:12]}_0x20.json").write_text(json.dumps({"cache_key": K3}),
                                                                         encoding="utf-8")
    recs = [{"cache_hit": True, "usage": _usage(0, 0), "wall_s": 0.01},
            {"cache_hit": False, "usage": _usage(200, 20), "wall_s": 5.0},
            {"cache_hit": False, "usage": _usage(150, 15), "wall_s": 4.0}]
    (d / "usage.json").write_text(json.dumps({"providers": [{"records": recs}]}), encoding="utf-8")
    return d


def test_arms_dedupe_keys_and_live_spend(tmp_path):
    cache = tmp_path / "cache"
    for k, i, o in ((K1, 100, 10), (K2, 200, 20), (K3, 150, 15)):
        _entry(cache, k, i, o)
    r = cost_report(_run(tmp_path), cache_root=cache)
    walk, base, union = r["arms"]["walk"], r["arms"]["baseline"], r["arms"]["union"]
    assert (walk["calls"], walk["input_tokens"], walk["output_tokens"]) == (2, 300, 30)
    assert (base["calls"], base["input_tokens"], base["output_tokens"]) == (2, 250, 25)   # K1 is shared
    assert (union["calls"], union["input_tokens"], union["output_tokens"]) == (3, 450, 45)
    assert union["missing_entries"] == 0 and union["usd"] == pytest.approx(0.00135)
    assert r["live"]["live_calls"] == 2 and r["live"]["input_tokens"] == 350 and r["live"]["model_s"] == 9.0


def test_cache_writes_come_from_attempt_details(tmp_path):
    cache = tmp_path / "cache"
    p = cache / K1[:2] / f"{K1}.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"key": K1, "identity": {"provider": "anthropic", "model": "claude-sonnet-5-5"},
                             "usage": _usage(100, 10, cached=3000),
                             "attempts": [{"detail": {"cache_creation_input_tokens": 3000}}]}), encoding="utf-8")
    u = usage_of([K1], cache)
    assert u["cache_write_input_tokens"] == 3000 and u["provider_cached_input_tokens"] == 3000
    assert dollars(u, "anthropic", "claude-sonnet-5-5") == pytest.approx(
        (100 * 2.0 + 3000 * 0.2 + 3000 * 2.5 + 10 * 10.0) / 1_000_000)


def test_dollars():
    u = _usage(1_000_000, 100_000, cached=1_000_000)
    assert dollars(u, "anthropic", "claude-sonnet-5-5") == pytest.approx(2.0 + 0.2 + 1.0)
    assert dollars(u, "ollama", "ornith:9b") == 0.0
    assert dollars(u, "anthropic", "some-unpriced-model") is None


def test_missing_entries_are_counted_and_bad_keys_rejected(tmp_path):
    cache = tmp_path / "cache"
    _entry(cache, K1, 10, 1)
    u = usage_of([K1, K1, K4], cache)
    assert u["calls"] == 1 and u["missing_entries"] == 1 and u["input_tokens"] == 10
    assert cache_entry(cache, K4) is None
    with pytest.raises(CostError, match="not a cache key"):
        cache_entry(cache, "zz")


@pytest.mark.corpus
def test_cost_of_the_phase6_gate_walk_from_the_real_cache():
    """Corpus-dependent (fails, never skips): 13 walked functions, 12 with a no-context row."""
    arms = cost_report(P6)["arms"]
    assert (arms["walk"]["calls"], arms["baseline"]["calls"], arms["union"]["calls"]) == (13, 13, 25)
    assert all(a["missing_entries"] == 0 and a["usd"] == 0.0 for a in arms.values())