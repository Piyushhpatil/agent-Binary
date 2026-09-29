"""Factory, usage accounting, and `llm ping`, all offline (FakeProvider or construction only)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

import taintwalk.llm.ping as ping_mod
from llm_fakes import FakeProvider, ok_response
from taintwalk.config import REPO_ROOT
from taintwalk.llm.anthropic_provider import AnthropicProvider
from taintwalk.llm.base import ProviderConfigError
from taintwalk.llm.cache import DiskCache
from taintwalk.llm.ollama_provider import OllamaProvider
from taintwalk.llm.registry import cache_dir, get_provider, load_providers_config, write_usage


def write_cfg(tmp_path: Path, **over: Any) -> Path:
    cfg: dict[str, Any] = {
        "cache_dir": str(tmp_path / "cache"),
        "default": "ollama",
        "retry": {"max_retries": 2, "backoff_base_s": 0.5, "backoff_cap_s": 4.0},
        "providers": {
            "anthropic": {"model": "claude-haiku-4-5-20251001", "params": {"max_tokens": 256}},
            "ollama": {"model": "ornith:9b", "digest": "a75697c14589",
                       "params": {"num_ctx": 16384, "num_predict": 1024}},
        },
    }
    cfg.update(over)
    p = tmp_path / "providers.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return p


# ---- factory --------------------------------------------------------------------------

def test_real_config_builds_both_providers_offline():
    cfg = load_providers_config()
    assert cache_dir(cfg) == REPO_ROOT / "runs/_cache/llm"
    a = get_provider("anthropic", use_cache=False)
    o = get_provider("ollama", use_cache=False)
    assert isinstance(a, AnthropicProvider) and a.model == "claude-sonnet-5-5"  # D-031
    assert a.params == {"max_tokens": 16000, "thinking": {"type": "adaptive"}, "effort": "high"}
    assert isinstance(o, OllamaProvider) and o.model == "ornith:9b"
    assert o.digest == "a75697c14589" and o.params["think"] is False
    assert o.params["num_ctx"] == 16384


def test_unknown_provider_is_a_config_error(tmp_path):
    with pytest.raises(ProviderConfigError, match="unknown provider"):
        get_provider("nope", config_path=write_cfg(tmp_path))


def test_default_provider_comes_from_config(tmp_path):
    assert get_provider(None, use_cache=False, config_path=write_cfg(tmp_path)).name == "ollama"


def test_cache_on_and_off(tmp_path):
    cfg = write_cfg(tmp_path)
    on = get_provider("ollama", config_path=cfg)
    off = get_provider("ollama", use_cache=False, config_path=cfg)
    assert isinstance(on.cache, DiskCache) and on.cache.root == tmp_path / "cache"
    assert off.cache is None


def test_relative_cache_dir_resolves_under_repo_root():
    assert cache_dir({"cache_dir": "runs/x"}) == REPO_ROOT / "runs/x"
    assert cache_dir({}) == REPO_ROOT / "runs/_cache/llm"


def test_retry_settings_and_overrides_reach_the_provider(tmp_path):
    cfg = write_cfg(tmp_path)
    p = get_provider("ollama", config_path=cfg)
    assert p.max_retries == 2 and p.backoff_cap_s == 4.0
    assert get_provider("ollama", config_path=cfg, max_retries=0).max_retries == 0


def test_missing_config_file_is_a_config_error(tmp_path):
    with pytest.raises(ProviderConfigError, match="not found"):
        load_providers_config(tmp_path / "absent.yaml")


# ---- usage ----------------------------------------------------------------------------

def test_write_usage_counts_hits_misses_and_tokens(tmp_path):
    cache = DiskCache(tmp_path / "c")
    prov = FakeProvider([ok_response(input_tokens=40, output_tokens=20)], cache=cache)
    prov.complete("sys", "int f(void);", ping_mod.PingReply, binary_sha256=None)
    prov.complete("sys", "int f(void);", ping_mod.PingReply, binary_sha256=None)  # cache hit
    doc = json.loads(write_usage(tmp_path / "run", [prov]).read_text(encoding="utf-8"))
    (rep,) = doc["providers"]
    assert rep["calls"] == 2 and rep["cache_hits"] == 1 and rep["failed"] == 0
    assert rep["tokens_spent"]["input_tokens"] == 40 and rep["tokens_spent"]["output_tokens"] == 20


# ---- ping -----------------------------------------------------------------------------

def _patch_provider(monkeypatch, factory) -> None:
    monkeypatch.setattr(ping_mod, "get_provider", lambda *a, **k: factory())


def test_ping_ok_then_cache_hit_with_zero_tokens(tmp_path, monkeypatch, capsys):
    cache = DiskCache(tmp_path / "c")
    scripts = [[ok_response()], []]  # second provider has nothing scripted: must be a hit
    _patch_provider(monkeypatch, lambda: FakeProvider(scripts.pop(0), cache=cache))
    assert ping_mod.run_ping("fake", run_dir=tmp_path / "run") == 0
    first = capsys.readouterr().out
    assert "MISS" in first and "PING OK" in first
    assert ping_mod.run_ping("fake", run_dir=tmp_path / "run") == 0
    second = capsys.readouterr().out
    assert "CACHE HIT" in second and "input 0  output 0" in second and "PING OK" in second
    assert (tmp_path / "run" / "usage.json").exists()


def test_ping_wrong_reply_fails(tmp_path, monkeypatch, capsys):
    wrong = ok_response(text='{"ok": true, "echo": "other", "count": 3}')
    _patch_provider(monkeypatch, lambda: FakeProvider([wrong], cache=None))
    assert ping_mod.run_ping("fake", run_dir=tmp_path / "run") == 1
    out = capsys.readouterr().out
    assert "mismatch" in out and "PING FAIL" in out


def test_ping_config_error_fails_cleanly(tmp_path, monkeypatch, capsys):
    def boom():
        raise ProviderConfigError("ANTHROPIC_API_KEY is not set")
    _patch_provider(monkeypatch, boom)
    assert ping_mod.run_ping("anthropic", run_dir=tmp_path / "run") == 1
    assert "PING FAIL" in capsys.readouterr().out


def test_ping_send_error_still_writes_usage(tmp_path, monkeypatch, capsys):
    _patch_provider(monkeypatch, lambda: FakeProvider(
        [ProviderConfigError("credit balance is too low")], cache=None))
    assert ping_mod.run_ping("fake", run_dir=tmp_path / "run") == 1
    out = capsys.readouterr().out
    assert "credit balance" in out and "PING FAIL" in out
    assert (tmp_path / "run" / "usage.json").exists()


class _PartlyOnCpu(FakeProvider):
    def residency(self) -> dict[str, Any]:
        return {"loaded": True, "gpu_pct": 76, "context_length": 16384}


def test_ping_fails_when_model_is_partly_on_cpu(tmp_path, monkeypatch, capsys):
    _patch_provider(monkeypatch, lambda: _PartlyOnCpu([ok_response()], cache=None))
    assert ping_mod.run_ping("fake", run_dir=tmp_path / "run") == 1
    out = capsys.readouterr().out
    assert "76% of model in VRAM" in out and "partly on CPU" in out and "PING FAIL" in out