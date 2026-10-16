"""Phase 8, mini-step 13 (throwaway, label-free): cloud cost per call and the D-031 thinking rule.

Reads the two probe runs' usage.json and their cache entries, plus the local run's persisted prompts for the
size of the whole job. No labels and no agreement. Prints per-call means, failure kinds, whether prompt
caching read anything, and the projected cost of both cloud arms (4,105 calls) against the $150 ceiling.
Projection: input tokens scale with prompt characters (the probe measures tokens per character on this
model); the system prompt is a cache read on every call except one write per program; output tokens
(thinking included) are the probe's mean per call.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from taintwalk.analysis.prompts import SYSTEM
from taintwalk.config import REPO_ROOT
from taintwalk.eval.cost import PRICES, cache_entry, default_cache_root, dollars

PROBES = (REPO_ROOT / "runs" / "p8-probe-dev", REPO_ROOT / "runs" / "p8-probe-heldout")
LOCAL = REPO_ROOT / "runs" / "p8-local"
MODEL, CALLS, PROGRAMS, CEILING = "claude-sonnet-5-5", 4105, 240, 150.0


def _chars(path: Path) -> int:
    return len(SYSTEM) + len(json.loads(path.read_text(encoding="utf-8"))["user"])


def main() -> int:
    cache, p = default_cache_root(), PRICES[MODEL]
    recs, probe_chars = [], 0
    for d in PROBES:
        doc = json.loads((d / "usage.json").read_text(encoding="utf-8"))
        recs += [r for prov in doc["providers"] for r in prov["records"]]
        probe_chars += sum(_chars(f) for f in (d / "prompts").glob("*.json"))
    kinds = Counter("ok" if r["status"] == "ok" else f"{r['status']}:{r['failure']}" for r in recs)
    u: Counter = Counter()
    n = 0
    for r in recs:
        e = cache_entry(cache, r["key"])
        if e is None or e["identity"].get("model") != MODEL:
            continue
        n += 1
        u.update({k: int(v) for k, v in e["usage"].items()})
        u["cache_write_input_tokens"] += sum(int((a.get("detail") or {}).get("cache_creation_input_tokens", 0) or 0)
                                             for a in e.get("attempts") or [])
        u["attempts"] += len(e.get("attempts") or [])
    if n == 0:
        print("PROBE FAIL: no Sonnet 5.5 cache entries behind the probe records")
        return 1
    spent = dollars(u, "anthropic", MODEL)
    per_char = (u["input_tokens"] + u["provider_cached_input_tokens"] + u["cache_write_input_tokens"]) / probe_chars
    sys_tok = per_char * len(SYSTEM)
    out_mean = u["output_tokens"] / n
    local = list(LOCAL.glob("tw-*/prompts/*.json")) + list(LOCAL.glob("tw-*/baseline/prompts/*.json"))
    in_total = per_char * sum(_chars(f) for f in local) * CALLS / len(local)
    reads, writes = (CALLS - PROGRAMS) * sys_tok, PROGRAMS * sys_tok
    parts = {"uncached input": (in_total - reads - writes) * p["input"], "cache reads": reads * p["cache_read"],
             "cache writes": writes * p["cache_write"], "output": out_mean * CALLS * p["output"]}
    projected = sum(parts.values()) / 1e6
    print(f"probe records      : {len(recs)} {dict(kinds)}; cache entries {n}; repairs {u['attempts'] - n}")
    print(f"per call (mean)    : input {u['input_tokens'] / n:.0f}, cache read {u['provider_cached_input_tokens'] / n:.0f}, "
          f"cache write {u['cache_write_input_tokens'] / n:.0f}, output {out_mean:.0f} (thinking {u['thinking_tokens'] / n:.0f})")
    print(f"prompt caching     : cache reads > 0: {'yes' if u['provider_cached_input_tokens'] > 0 else 'NO'}")
    print(f"tokens per char    : {per_char:.3f}; system prompt ~ {sys_tok:.0f} tokens")
    print(f"probe spend        : ${spent:.2f}")
    print(f"full job           : {CALLS} calls; local prompts measured {len(local)}, scaled to {CALLS}")
    print("projection         : " + ", ".join(f"{k} ${v / 1e6:.2f}" for k, v in parts.items()) + f" = ${projected:.2f}")
    keep = spent + projected <= CEILING
    print(f"ceiling ${CEILING:.0f}       : spent + projected ${spent + projected:.2f} -> "
          + ("KEEP adaptive thinking (D-031)" if keep else "SWITCH to between_tools, max_tokens 2048 (D-031)"))
    ok = n == len(recs) and u["provider_cached_input_tokens"] > 0
    print("PROBE OK" if ok else "PROBE CHECK: see the lines above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())