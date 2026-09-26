"""`taintwalk llm ping`: one tiny structured call through the full provider pipeline
(leak gate -> cache -> send -> validate -> usage), proving a backend works end to end.

Passes only if the reply is exactly the expected JSON, and, for a backend that reports
GPU residency, the model sat 100% in VRAM on a fresh call. Silent CPU fallback fails.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from taintwalk.config import REPO_ROOT
from taintwalk.llm.base import LLMError
from taintwalk.llm.registry import get_provider, write_usage

PING_SYSTEM = "Reply only with JSON matching the schema."
PING_USER = 'Set ok to true, echo to the string "taintwalk", and count to 3.'
EXPECTED = {"ok": True, "echo": "taintwalk", "count": 3}
DEFAULT_RUN_DIR = Path("runs/p4-ping")


class PingReply(BaseModel):
    ok: bool
    echo: str
    count: int = Field(ge=0, le=10)


def _show(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def run_ping(
    provider_name: str | None,
    *,
    use_cache: bool = True,
    retry_failed: bool = False,
    run_dir: str | Path | None = None,
    config_path: Path | None = None,
) -> int:
    run_dir = Path(run_dir) if run_dir else DEFAULT_RUN_DIR
    if not run_dir.is_absolute():
        run_dir = REPO_ROOT / run_dir

    try:
        provider = get_provider(provider_name, use_cache=use_cache, config_path=config_path)
    except LLMError as e:
        print(f"PING FAIL: {type(e).__name__}: {e}")
        return 1

    ident = provider.identity()
    digest = f"  digest {ident['digest']}" if "digest" in ident else ""
    print(f"provider   : {provider.name}  model {provider.model}{digest}")
    print(f"cache      : {'on' if provider.cache is not None else 'OFF (--no-cache)'}")

    t0 = time.monotonic()
    try:
        comp = provider.complete(PING_SYSTEM, PING_USER, PingReply,
                                 binary_sha256=None, retry_failed=retry_failed)
    except LLMError as e:
        out = write_usage(run_dir, [provider])
        print(f"PING FAIL: {type(e).__name__}: {e}")
        print(f"usage      : {_show(out)}")
        return 1
    wall = time.monotonic() - t0

    ok = comp.ok and comp.data == EXPECTED
    u = comp.usage
    print(f"result     : {'CACHE HIT' if comp.cache_hit else 'MISS'}  status {comp.status}  "
          f"attempts {len(comp.attempts)}  repaired {'yes' if comp.repaired else 'no'}")
    print(f"reply      : {json.dumps(comp.data) if comp.data is not None else repr(comp.raw_text)}")
    print(f"tokens     : input {u.input_tokens}  output {u.output_tokens}  (this call; a cache hit costs 0)")
    print(f"latency    : {wall:.2f} s")
    if not comp.ok:
        print(f"failure    : {comp.failure}")
    elif comp.data != EXPECTED:
        print(f"mismatch   : expected {json.dumps(EXPECTED)}")

    residency = getattr(provider, "residency", None)
    if callable(residency):
        try:
            r: dict[str, Any] = residency()
        except LLMError as e:
            r = {"error": str(e)}
        if r.get("loaded"):
            print(f"gpu        : {r['gpu_pct']}% of model in VRAM  (context {r.get('context_length')})")
            if not comp.cache_hit and r["gpu_pct"] < 100:
                print("gpu        : FAIL: model is partly on CPU")
                ok = False
        elif "error" in r:
            print(f"gpu        : unknown ({r['error']})")
        else:
            print("gpu        : model not loaded" + (" (reply served from cache)" if comp.cache_hit else ""))
            if not comp.cache_hit:
                ok = False

    out = write_usage(run_dir, [provider])
    print(f"usage      : {_show(out)}")
    print("PING OK" if ok else "PING FAIL")
    return 0 if ok else 1