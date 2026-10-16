"""Test helper (Phase 11, D-043): real corpus identifiers read from the committed manifest, so a test that
only needs a real sha256 (to keep the leak gate's name layer armed, D-017) needs nothing under runs/."""
import json
from functools import lru_cache

from taintwalk.config import REPO_ROOT


@lru_cache(maxsize=None)
def _entries() -> dict:
    doc = json.loads((REPO_ROOT / "corpus" / "manifest.json").read_text(encoding="utf-8"))
    return {e["case_id"]: e for e in doc["entries"]}


def corpus_sha(case_id: str) -> str:
    """The stripped binary's sha256 for a corpus case: the key the leak gate looks a program up by."""
    return _entries()[case_id]["stripped_sha256"]