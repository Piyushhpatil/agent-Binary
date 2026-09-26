"""D-017 at the provider boundary: the leak gate runs before any cache or network I/O.

Every negative test is paired with evidence the path is live (a positive control, a
planted cache entry that is provably present), so none of them can pass vacuously.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from llm_fakes import FakeProvider, Ping, ok_response
from taintwalk.llm.cache import DiskCache, cache_key
from taintwalk.util.leakcheck import LeakCheckConfigError, LeakError, assert_clean

SYSTEM = "You analyze decompiled C functions for data flow."
CLEAN_USER = "int f(int a) { return a + 1; }"
LEAKY_USER = "void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad(void) { }"
LEAKY_SYSTEM = "Known label: CWE121 / CWE-121. " + SYSTEM


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


def _real_leak_error() -> LeakError:
    try:
        assert_clean(LEAKY_USER, None)
    except LeakError as e:
        return e
    raise AssertionError("gate did not fire on the canary; every test below would be vacuous")


def test_clean_prompt_is_sent_once_and_cached(tmp_path):
    cache_dir = tmp_path / "cache"
    prov = FakeProvider([ok_response()], cache=DiskCache(cache_dir))
    comp = prov.complete(SYSTEM, CLEAN_USER, Ping, binary_sha256=None)
    assert comp.ok and comp.data == {"ok": True, "echo": "taintwalk", "count": 3}
    assert len(prov.calls) == 1
    assert len(_files(cache_dir)) == 1


def test_leaking_user_prompt_never_reaches_provider_or_cache(tmp_path):
    cache_dir = tmp_path / "cache"
    prov = FakeProvider([ok_response()], cache=DiskCache(cache_dir))
    with pytest.raises(LeakError):
        prov.complete(SYSTEM, LEAKY_USER, Ping, binary_sha256=None)
    assert prov.calls == []
    assert _files(cache_dir) == []
    assert prov.records == []


def test_leaking_system_prompt_never_reaches_provider_or_cache(tmp_path):
    cache_dir = tmp_path / "cache"
    prov = FakeProvider([ok_response()], cache=DiskCache(cache_dir))
    with pytest.raises(LeakError):
        prov.complete(LEAKY_SYSTEM, CLEAN_USER, Ping, binary_sha256=None)
    assert prov.calls == []
    assert _files(cache_dir) == []


def test_leak_gate_runs_before_a_cache_hit(tmp_path):
    cache = DiskCache(tmp_path / "cache")
    warm = FakeProvider([ok_response()], cache=cache)
    comp = warm.complete(SYSTEM, CLEAN_USER, Ping, binary_sha256=None)

    leaky_key = cache_key(warm.identity(), SYSTEM, LEAKY_USER, Ping.model_json_schema())
    entry = cache.get(comp.key)
    entry["key"] = leaky_key
    cache.put(leaky_key, entry)
    assert cache.get(leaky_key) is not None, "planted entry missing; test would be vacuous"

    prov = FakeProvider([], cache=cache)
    with pytest.raises(LeakError):
        prov.complete(SYSTEM, LEAKY_USER, Ping, binary_sha256=None)
    assert prov.calls == []
    assert prov.records == []


def test_unknown_binary_fails_closed_before_send(tmp_path):
    prov = FakeProvider([ok_response()], cache=DiskCache(tmp_path / "cache"))
    with pytest.raises(LeakCheckConfigError):
        prov.complete(SYSTEM, CLEAN_USER, Ping, binary_sha256="0" * 64)
    assert prov.calls == []


def test_binary_sha256_is_a_required_keyword():
    prov = FakeProvider([ok_response()], cache=None)
    with pytest.raises(TypeError):
        prov.complete(SYSTEM, CLEAN_USER, Ping)  # no binary_sha256: must not default to static-only
    assert prov.calls == []


def test_leak_error_raised_during_send_is_not_swallowed(tmp_path):
    cache_dir = tmp_path / "cache"
    prov = FakeProvider([_real_leak_error()], cache=DiskCache(cache_dir))
    with pytest.raises(LeakError):
        prov.complete(SYSTEM, CLEAN_USER, Ping, binary_sha256=None)
    assert len(prov.calls) == 1
    assert _files(cache_dir) == []
    assert prov.records == []
