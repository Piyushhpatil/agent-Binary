"""I3 / D-019: the cache key covers everything that determines output, hits are free,
terminal failures replay identically, and every form of corruption fails closed."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import taintwalk.llm.cache as cache_mod
from llm_fakes import FakeProvider, Ping, ok_response
from taintwalk.llm.base import STOP_REFUSAL, Usage
from taintwalk.llm.cache import CACHE_FORMAT, CacheCorrupt, DiskCache, cache_key, canonical_json

SYSTEM = "You analyze decompiled C functions for data flow."
USER = "int f(int a) { return a + 1; }"
IDENTITY = {"provider": "fake", "model": "fake-1", "params": {"p": 1}}
SCHEMA = Ping.model_json_schema()
BASE = dict(identity=IDENTITY, system=SYSTEM, user=USER, schema=SCHEMA)


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


def _run(prov: FakeProvider, user: str = USER, **kw):
    return prov.complete(SYSTEM, user, Ping, binary_sha256=None, **kw)


# ---- key ------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field,changed",
    [
        ("identity", {**IDENTITY, "model": "fake-2"}),
        ("identity", {**IDENTITY, "params": {"p": 2}}),
        ("identity", {**IDENTITY, "digest": "abc123"}),
        ("system", SYSTEM + " "),
        ("user", USER + "\n"),
        ("schema", {**SCHEMA, "title": "Other"}),
    ],
    ids=["model", "params", "digest", "system", "user", "schema"],
)
def test_key_changes_when_any_input_changes(field, changed):
    assert cache_key(**{**BASE, field: changed}) != cache_key(**BASE)


def test_key_is_stable_under_dict_ordering():
    reordered = {"params": {"p": 1}, "model": "fake-1", "provider": "fake"}
    assert cache_key(**{**BASE, "identity": reordered}) == cache_key(**BASE)
    assert len(cache_key(**BASE)) == 64


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


# ---- hits and misses -------------------------------------------------------------------

def test_hit_costs_zero_tokens_and_never_calls_provider(tmp_path):
    cache = DiskCache(tmp_path / "c")
    first = FakeProvider([ok_response(input_tokens=40, output_tokens=20)], cache=cache)
    a = _run(first)
    assert not a.cache_hit and a.usage == Usage(input_tokens=40, output_tokens=20)

    second = FakeProvider([], cache=cache)  # nothing scripted: any send would raise
    b = _run(second)
    assert b.cache_hit and b.usage == Usage() and second.token_usage.total == 0
    assert second.calls == []
    assert (b.key, b.data, b.raw_text) == (a.key, a.data, a.raw_text)


def test_different_params_do_not_share_an_entry(tmp_path):
    cache = DiskCache(tmp_path / "c")
    _run(FakeProvider([ok_response()], cache=cache))
    other = FakeProvider([ok_response()], params={"p": 2}, cache=cache)
    c = _run(other)
    assert not c.cache_hit and len(other.calls) == 1
    assert len(_files(tmp_path / "c")) == 2


def test_terminal_failure_is_cached_and_replayed(tmp_path):
    cache = DiskCache(tmp_path / "c")
    refused = ok_response(text="", stop_reason=STOP_REFUSAL, category="cyber")
    a = _run(FakeProvider([refused], cache=cache))
    assert a.status == "failed" and a.failure == "refusal:cyber"

    second = FakeProvider([], cache=cache)
    b = _run(second)
    assert b.cache_hit and b.failure == "refusal:cyber" and second.calls == []


def test_retry_failed_bypasses_a_cached_failure(tmp_path):
    cache = DiskCache(tmp_path / "c")
    _run(FakeProvider([ok_response(text="", stop_reason=STOP_REFUSAL)], cache=cache))

    retry = FakeProvider([ok_response()], cache=cache)
    r = _run(retry, retry_failed=True)
    assert r.ok and not r.cache_hit and len(retry.calls) == 1

    after = FakeProvider([], cache=cache)
    assert _run(after).ok and after.calls == []  # the success replaced the failure


def test_no_cache_means_no_files_and_always_sends(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prov = FakeProvider([ok_response(), ok_response()], cache=None)
    _run(prov)
    _run(prov)
    assert len(prov.calls) == 2
    assert _files(tmp_path) == []


# ---- corruption fails closed ----------------------------------------------------------

def test_corrupt_entry_raises_instead_of_missing(tmp_path):
    cache = DiskCache(tmp_path / "c")
    a = _run(FakeProvider([ok_response()], cache=cache))
    cache.path_for(a.key).write_text("{not json", encoding="utf-8")
    prov = FakeProvider([ok_response()], cache=cache)
    with pytest.raises(CacheCorrupt):
        _run(prov)
    assert prov.calls == []


def test_entry_under_the_wrong_key_raises(tmp_path):
    cache = DiskCache(tmp_path / "c")
    a = _run(FakeProvider([ok_response()], cache=cache))
    p = cache.path_for(a.key)
    entry = json.loads(p.read_text(encoding="utf-8"))
    entry["key"] = "f" * 64
    p.write_text(json.dumps(entry), encoding="utf-8")
    with pytest.raises(CacheCorrupt):
        cache.get(a.key)


def test_entry_missing_fields_raises(tmp_path):
    cache = DiskCache(tmp_path / "c")
    a = _run(FakeProvider([ok_response()], cache=cache))
    p = cache.path_for(a.key)
    entry = json.loads(p.read_text(encoding="utf-8"))
    del entry["data"]
    p.write_text(json.dumps(entry), encoding="utf-8")
    prov = FakeProvider([ok_response()], cache=cache)
    with pytest.raises(CacheCorrupt):
        _run(prov)
    assert prov.calls == []


def test_put_refuses_mismatched_key_or_format(tmp_path):
    cache = DiskCache(tmp_path / "c")
    with pytest.raises(ValueError):
        cache.put("a" * 64, {"key": "b" * 64, "format": CACHE_FORMAT})
    with pytest.raises(ValueError):
        cache.put("a" * 64, {"key": "a" * 64, "format": CACHE_FORMAT + 1})
    assert _files(tmp_path / "c") == []


def test_path_rejects_non_hex_keys(tmp_path):
    with pytest.raises(ValueError):
        DiskCache(tmp_path).path_for("../../etc/passwd")


# ---- atomic writes --------------------------------------------------------------------

def test_writes_leave_no_temp_files(tmp_path):
    cache = DiskCache(tmp_path / "c")
    prov = FakeProvider([ok_response(), ok_response(), ok_response()], cache=cache)
    for i in range(3):
        _run(prov, user=f"int f{i}(void) {{ return {i}; }}")
    files = _files(tmp_path / "c")
    assert len(files) == 3
    assert not any(p.name.startswith(".tmp-") for p in files)


def test_failed_write_leaves_nothing_behind(tmp_path, monkeypatch):
    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(cache_mod.os, "fsync", boom)
    cache = DiskCache(tmp_path / "c")
    key = "a" * 64
    with pytest.raises(OSError):
        cache.put(key, {"key": key, "format": CACHE_FORMAT})
    assert _files(tmp_path / "c") == []