"""Build LLM providers from config/providers.yaml, and write usage accounting.

Phase 5 onward calls get_provider() and never imports a backend module, so analysis code
never knows which backend it is talking to. Backends are imported lazily: an Ollama-only
run never loads the Anthropic SDK.

usage.json counts every call, including calls that raised after spending tokens (status
"raised", D-032), and says whether the provider ran in offline (replay-only) mode.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from taintwalk.config import REPO_ROOT
from taintwalk.llm.base import LLMProvider, ProviderConfigError
from taintwalk.llm.cache import DiskCache

PROVIDERS_YAML = REPO_ROOT / "config" / "providers.yaml"
DEFAULT_CACHE_DIR = "runs/_cache/llm"


def load_providers_config(path: Path | None = None) -> dict[str, Any]:
    p = Path(path) if path is not None else PROVIDERS_YAML
    try:
        cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ProviderConfigError(f"provider config not found: {p}") from e
    if not isinstance(cfg, dict) or not isinstance(cfg.get("providers"), dict):
        raise ProviderConfigError(f"{p}: expected a mapping with a 'providers' section")
    return cfg


def cache_dir(cfg: dict[str, Any]) -> Path:
    d = Path(cfg.get("cache_dir") or DEFAULT_CACHE_DIR)
    return d if d.is_absolute() else REPO_ROOT / d


def get_provider(
    name: str | None = None,
    *,
    use_cache: bool = True,
    offline: bool = False,
    config_path: Path | None = None,
    **overrides: Any,
) -> LLMProvider:
    """Build one provider. `overrides` replace retry settings (e.g. max_retries=0).
    offline=True is replay only: a cache miss raises OfflineMiss before any network I/O."""
    if offline and not use_cache:
        raise ProviderConfigError("offline mode replays from the disk cache; drop --no-cache")
    cfg = load_providers_config(config_path)
    name = name or cfg.get("default")
    spec = cfg["providers"].get(name)
    if not isinstance(spec, dict):
        raise ProviderConfigError(
            f"unknown provider {name!r}; configured: {sorted(cfg['providers'])}"
        )
    if not spec.get("model"):
        raise ProviderConfigError(f"provider {name!r} has no model configured")

    retry = dict(cfg.get("retry") or {})
    retry.update(overrides)
    common: dict[str, Any] = {"cache": DiskCache(cache_dir(cfg)) if use_cache else None, **retry}
    params = dict(spec.get("params") or {})

    if name == "anthropic":
        from taintwalk.llm.anthropic_provider import AnthropicProvider
        prov = AnthropicProvider(
            spec["model"], params, timeout_s=float(spec.get("timeout_s", 120)), **common
        )
    elif name == "ollama":
        from taintwalk.llm.ollama_provider import DEFAULT_BASE_URL, OllamaProvider
        prov = OllamaProvider(
            spec["model"],
            params,
            digest=str(spec.get("digest") or ""),
            base_url=str(spec.get("base_url") or DEFAULT_BASE_URL),
            timeout_s=float(spec.get("timeout_s", 600)),
            **common,
        )
    else:
        raise ProviderConfigError(f"provider {name!r} is configured but has no backend in this build")
    prov.offline = offline
    return prov


def usage_report(provider: LLMProvider) -> dict[str, Any]:
    recs = provider.records
    return {
        "identity": provider.identity(),
        "offline": provider.offline,
        "calls": len(recs),
        "cache_hits": sum(1 for r in recs if r["cache_hit"]),
        "failed": sum(1 for r in recs if r["status"] == "failed"),
        "raised": sum(1 for r in recs if r["status"] == "raised"),
        "repaired": sum(1 for r in recs if r["repaired"]),
        "transient_retries": provider.transient_retries,
        "tokens_spent": asdict(provider.token_usage),
        "records": recs,
    }


def write_usage(run_dir: Path, providers: list[LLMProvider]) -> Path:
    """runs/<id>/usage.json: per-provider calls, cache hits, failures, tokens spent.
    Holds cache keys and counts only, never prompts."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    out = run_dir / "usage.json"
    doc = {
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "providers": [usage_report(p) for p in providers],
    }
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out