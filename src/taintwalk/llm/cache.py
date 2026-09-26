"""Content-addressed disk cache for LLM completions (Invariant I3, D-019).

The key covers everything that determines a completion: provider identity (name,
model, model version or digest, generation parameters), the system prompt, the user
prompt, the output schema, and CACHE_FORMAT. Change any of them and the key changes.

Terminal outcomes are cached, including schema failures and refusals, so an unchanged
re-run costs zero tokens and replays identically (I2). Transient errors are never cached.

A corrupt or mismatched entry raises CacheCorrupt. It is never treated as a silent miss:
a silent miss would re-call the model, pay again, and possibly change the answer.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

CACHE_FORMAT = 1
_HEX = frozenset("0123456789abcdef")


class CacheCorrupt(RuntimeError):
    """A cache file exists but cannot be trusted. Fails closed."""


def canonical_json(obj: Any) -> str:
    """One byte-stable serialization: sorted keys, no whitespace, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def cache_key(identity: Mapping[str, Any], system: str, user: str, schema: Mapping[str, Any]) -> str:
    payload = {
        "format": CACHE_FORMAT,
        "identity": dict(identity),
        "system": system,
        "user": user,
        "schema": dict(schema),
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class DiskCache:
    """root/<first two hex chars>/<key>.json, written atomically."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def path_for(self, key: str) -> Path:
        if len(key) != 64 or not set(key) <= _HEX:
            raise ValueError(f"not a sha256 hex key: {key!r}")
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        p = self.path_for(key)
        try:
            raw = p.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as e:
            raise CacheCorrupt(f"{p}: not valid JSON ({e.msg})") from e
        if not isinstance(entry, dict) or entry.get("format") != CACHE_FORMAT or entry.get("key") != key:
            raise CacheCorrupt(f"{p}: format or key mismatch")
        return entry

    def put(self, key: str, entry: Mapping[str, Any]) -> Path:
        if entry.get("key") != key or entry.get("format") != CACHE_FORMAT:
            raise ValueError("entry must carry its own key and the current CACHE_FORMAT")
        p = self.path_for(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(canonical_json(dict(entry)))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        return p
