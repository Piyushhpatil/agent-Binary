"""Offline replay and raised-call accounting in the shared LLM pipeline (Phase 8, D-032).

Offline mode: a cache miss raises before any send and before any cache write.
Accounting: a call that raises after spending tokens is still recorded with those tokens.
Only LLMError is recorded, so a LeakError (never an LLMError) passes through untouched.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from llm_fakes import FakeProvider, Ping, ok_response
from taintwalk.llm.base import (
    STOP_MAX_TOKENS,
    STOP_OVERFLOW,
    ContextOverflow,
    LLMError,
    OfflineMiss,
    ProviderConfigError,
    RetryExhausted,
    TransientError,
)
from taintwalk.llm.cache import DiskCache
from taintwalk.llm.registry import get_provider, write_usage
from taintwalk.util.leakcheck import LeakError

SYS = "Reply only with JSON matching the schema."
USER = "int f(void);"


def _cfg(tmp_path: Path) -> Path:
    cfg = {
        "cache_dir": str(tmp_path / "cache"),
        "default": "ollama",
        "retry": {"max_retries": 0},
        "providers": {
            "ollama": {"model": "ornith:9b", "digest": "a75697c14589",
                       "params": {"num_ctx": 16384, "num_predict": 1024}},
        },
    }
    p = tmp_path / "providers.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return p


def _files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


def _usage(tmp_path: Path, prov: FakeProvider) -> dict:
    doc = json.loads(write_usage(tmp_path / "run", [prov]).read_text(encoding="utf-8"))
    (rep,) = doc["providers"]
    return rep


# ---- offline mode ---------------------------------------------------------------------

def test_offline_hit_replays_at_zero_tokens(tmp_path):
    cache = DiskCache(tmp_path / "c")
    FakeProvider([ok_response()], cache=cache).complete(SYS, USER, Ping, binary_sha256=None)
    replay = FakeProvider([], cache=cache, offline=True)  # nothing scripted: any send would fail
    comp = replay.complete(SYS, USER, Ping, binary_sha256=None)
    assert comp.ok and comp.cache_hit and comp.usage.total == 0 and replay.calls == []
    rep = _usage(tmp_path, replay)
    assert rep["offline"] is True and rep["calls"] == 1 and rep["cache_hits"] == 1
    assert rep["raised"] == 0 and rep["tokens_spent"]["input_tokens"] == 0


def test_offline_miss_raises_before_any_send_or_cache_write(tmp_path):
    root = tmp_path / "c"
    prov = FakeProvider([ok_response()], cache=DiskCache(root), offline=True)
    before = _files(root)
    with pytest.raises(OfflineMiss):
        prov.complete(SYS, USER, Ping, binary_sha256=None)
    assert prov.calls == [] and len(prov.responses) == 1
    assert _files(root) == before
    assert prov.records == []  # no call was made, so there is nothing to account for


def test_offline_replays_a_cached_failure_but_retry_failed_is_a_miss(tmp_path):
    cache = DiskCache(tmp_path / "c")
    cut_off = ok_response(text='{"ok": tr', stop_reason=STOP_MAX_TOKENS)
    FakeProvider([cut_off], cache=cache).complete(SYS, USER, Ping, binary_sha256=None)
    replay = FakeProvider([], cache=cache, offline=True)
    comp = replay.complete(SYS, USER, Ping, binary_sha256=None)
    assert comp.cache_hit and comp.failure == STOP_MAX_TOKENS
    with pytest.raises(OfflineMiss):
        replay.complete(SYS, USER, Ping, binary_sha256=None, retry_failed=True)
    assert replay.calls == []


def test_offline_needs_the_disk_cache(tmp_path):
    with pytest.raises(ProviderConfigError, match="offline"):
        FakeProvider([], cache=None, offline=True)
    with pytest.raises(ProviderConfigError, match="offline"):
        get_provider("ollama", use_cache=False, offline=True, config_path=_cfg(tmp_path))


def test_get_provider_sets_offline_only_when_asked(tmp_path):
    cfg = _cfg(tmp_path)
    assert get_provider("ollama", config_path=cfg).offline is False
    assert get_provider("ollama", offline=True, config_path=cfg).offline is True


# ---- raised-call accounting -------------------------------------------------------------

def test_overflow_after_a_reply_is_recorded_with_its_tokens(tmp_path):
    root = tmp_path / "c"
    overflow = ok_response(text="", stop_reason=STOP_OVERFLOW, input_tokens=900, output_tokens=0)
    prov = FakeProvider([overflow], cache=DiskCache(root))
    before = _files(root)
    with pytest.raises(ContextOverflow):
        prov.complete(SYS, USER, Ping, binary_sha256=None)
    (rec,) = prov.records
    assert rec["status"] == "raised" and rec["failure"] == "ContextOverflow"
    assert rec["usage"]["input_tokens"] == 900 and rec["attempts"] == 1 and rec["cache_hit"] is False
    assert prov.token_usage.input_tokens == 900
    assert _files(root) == before  # still never cached (D-019)
    rep = _usage(tmp_path, prov)
    assert rep["calls"] == 1 and rep["raised"] == 1 and rep["failed"] == 0
    assert rep["tokens_spent"]["input_tokens"] == 900


def test_first_attempt_tokens_survive_a_failed_repair():
    first = ok_response(text="not json", input_tokens=40, output_tokens=20)
    prov = FakeProvider([first, TransientError("503")], cache=None, max_retries=0)
    with pytest.raises(RetryExhausted):
        prov.complete(SYS, USER, Ping, binary_sha256=None)
    (rec,) = prov.records
    assert rec["status"] == "raised" and rec["failure"] == "RetryExhausted"
    assert rec["repaired"] is True and rec["attempts"] == 1
    assert rec["usage"]["input_tokens"] == 40 and rec["usage"]["output_tokens"] == 20


def test_non_llm_errors_pass_through_unrecorded():
    """Only LLMError is caught and recorded; anything else passes through, as a LeakError must."""
    prov = FakeProvider([RuntimeError("boom")], cache=None)
    with pytest.raises(RuntimeError, match="boom"):
        prov.complete(SYS, USER, Ping, binary_sha256=None)
    assert prov.records == []


def test_leak_error_is_not_an_llm_error():
    """D-017/D-019: the pipeline never catches a LeakError. Recording catches LLMError only,
    so this must stay true for the rule to hold."""
    assert not issubclass(LeakError, LLMError)