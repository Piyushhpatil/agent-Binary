"""Tokens, time and dollars for Phase 8 runs (D-032).

Tokens come from the LLM cache, not from usage.json: a cache entry keeps the usage of the call that
produced it, while a replay rewrites usage.json with zeros. Every walk row file (summaries/<stem>.json)
and every no-context row file (baseline/summaries/<stem>.json) names its cache key, so an arm's cost is
the sum over its distinct keys, whether or not this particular run paid for them:
  walk arm        the walk rows;
  no-context arm  the baseline rows plus the walk rows of functions with no callee block (the same
                  prompt, hence the same key);
  union           running both arms together.
live_spent() is what one run actually paid: usage.json records that were not cache hits (valid only
for a run dir that was never replayed in place; it does not see cache writes).

Dollars use PRICES (USD per million tokens) as published on PRICES_AS_OF at PRICES_SOURCE. The table
lives here, not in config/, because running walks read config/ (D-032 freeze). A local model costs 0.
Anthropic's usage splits the prompt three ways (prompt-caching docs): input_tokens are the tokens after
the cache breakpoint; cache reads (provider_cached_input_tokens) and cache writes (each attempt's
detail cache_creation_input_tokens) are separate fields, each at its own price.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import yaml

from taintwalk.config import REPO_ROOT
from taintwalk.eval.score import discover_runs

PRICES_AS_OF = "2026-09-29"
PRICES_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing"
PRICES = {
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00, "cache_read": 0.20, "cache_write": 2.50},
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00, "cache_read": 0.10, "cache_write": 1.25},
}
LOCAL_PROVIDERS = frozenset({"ollama"})
USAGE_FIELDS = ("input_tokens", "output_tokens", "thinking_tokens", "provider_cached_input_tokens")
KEY_RE = re.compile(r"^[0-9a-f]{64}$")


class CostError(RuntimeError):
    """A run or the cache is not in the shape the cost report needs; nothing is reported."""


def default_cache_root() -> Path:
    """cache_dir from config/providers.yaml, read as plain YAML so no taintwalk.llm module loads."""
    cfg = yaml.safe_load((REPO_ROOT / "config" / "providers.yaml").read_text(encoding="utf-8"))
    d = Path(cfg.get("cache_dir") or "runs/_cache/llm")
    return d if d.is_absolute() else REPO_ROOT / d


def cache_entry(cache_root: Path, key: str) -> dict[str, Any] | None:
    """The entry for a key, or None when it is not cached (a call that raised is never cached)."""
    if not KEY_RE.match(key):
        raise CostError(f"not a cache key: {key[:20]!r}")
    p = Path(cache_root) / key[:2] / f"{key}.json"
    if not p.exists():
        return None
    entry = json.loads(p.read_text(encoding="utf-8"))
    if entry.get("key") != key:
        raise CostError(f"cache file {p.name} holds key {str(entry.get('key'))[:16]}")
    return entry


def _row_key(path: Path) -> str:
    if not path.exists():
        raise CostError(f"{path} is missing")
    key = json.loads(path.read_text(encoding="utf-8")).get("cache_key")
    if not key:
        raise CostError(f"{path} names no cache key")
    return key


def arm_keys(run_dir: Path) -> dict[str, set[str]]:
    """Cache keys of each arm in one walk run dir. The no-context arm is empty without --with-baseline."""
    run_dir = Path(run_dir)
    walk = json.loads((run_dir / "walk.json").read_text(encoding="utf-8"))
    sha, base = walk["binary_sha256"], walk.get("baseline") or {}
    walk_keys: set[str] = set()
    base_keys: set[str] = set()
    for a, fn in walk["functions"].items():
        name = f"{sha[:12]}_{a}.json"
        k = _row_key(run_dir / "summaries" / name)
        walk_keys.add(k)
        if a in base:
            base_keys.add(_row_key(run_dir / "baseline" / "summaries" / name))
        elif base and not fn["context_chars"]:
            base_keys.add(k)
    return {"walk": walk_keys, "baseline": base_keys}


def usage_of(keys: Iterable[str], cache_root: Path) -> dict[str, Any]:
    """Original usage summed over distinct keys, read from their cache entries (cache writes from
    each attempt's detail)."""
    tot = dict.fromkeys(USAGE_FIELDS, 0)
    models: Counter = Counter()
    calls = missing = writes = 0
    for k in sorted(set(keys)):
        e = cache_entry(cache_root, k)
        if e is None:
            missing += 1
            continue
        calls += 1
        for f in USAGE_FIELDS:
            tot[f] += int(e["usage"].get(f, 0))
        writes += sum(int((a.get("detail") or {}).get("cache_creation_input_tokens", 0) or 0)
                      for a in e.get("attempts") or [])
        ident = e.get("identity") or {}
        models[(str(ident.get("provider")), str(ident.get("model")))] += 1
    return {"calls": calls, "missing_entries": missing, **tot, "cache_write_input_tokens": writes,
            "models": [{"provider": p, "model": m, "calls": n} for (p, m), n in sorted(models.items())]}


def dollars(usage: dict[str, Any], provider: str, model: str) -> float | None:
    """USD at PRICES. A local model costs 0; an unpriced model gives None."""
    if provider in LOCAL_PROVIDERS:
        return 0.0
    p = PRICES.get(model)
    if p is None:
        return None
    cost = (usage["input_tokens"] * p["input"]
            + usage["provider_cached_input_tokens"] * p["cache_read"]
            + usage.get("cache_write_input_tokens", 0) * p["cache_write"]
            + usage["output_tokens"] * p["output"]) / 1_000_000
    return round(cost, 6)


def live_spent(run_dir: Path) -> dict[str, Any]:
    """What one run paid when it ran: usage.json records that were not cache hits."""
    doc = json.loads((Path(run_dir) / "usage.json").read_text(encoding="utf-8"))
    recs = [r for p in doc["providers"] for r in p["records"]]
    live = [r for r in recs if not r["cache_hit"]]
    return {"records": len(recs), "live_calls": len(live),
            **{f: sum(int(r["usage"].get(f, 0)) for r in live) for f in USAGE_FIELDS},
            "model_s": round(sum(float(r["wall_s"]) for r in live), 1)}


def cost_report(root: Path, cache_root: Path | None = None) -> dict[str, Any]:
    """Per-arm and union cost of every walk run dir at or under root, plus what those runs paid live."""
    runs = discover_runs(Path(root))
    if not runs:
        raise CostError(f"no walk run dir at or under {root}")
    cache_root = Path(cache_root) if cache_root is not None else default_cache_root()
    walk_keys: set[str] = set()
    base_keys: set[str] = set()
    live: Counter = Counter()
    for d in runs:
        k = arm_keys(d)
        walk_keys |= k["walk"]
        base_keys |= k["baseline"]
        if (d / "usage.json").exists():
            for f, v in live_spent(d).items():
                live[f] += v
    arms: dict[str, Any] = {}
    for arm, ks in (("walk", walk_keys), ("baseline", base_keys), ("union", walk_keys | base_keys)):
        u = usage_of(ks, cache_root)
        one = u["models"][0] if len(u["models"]) == 1 else None
        arms[arm] = {**u, "usd": dollars(u, one["provider"], one["model"]) if one else None}
    return {"programs": len(runs), "prices_as_of": PRICES_AS_OF, "prices_source": PRICES_SOURCE,
            "arms": arms, "live": {k: (round(v, 1) if k == "model_s" else v) for k, v in live.items()}}