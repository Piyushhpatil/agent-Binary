"""D-041: an offline replay re-derives a preflight context overflow exactly as the live run did.

An overflow is never cached (D-022), so before D-041 an offline replay of a run with one stopped at
OfflineMiss. The preflight is local (a character count), so running it before the miss costs no I/O.
"""
from __future__ import annotations

import pytest

from llm_fakes import FakeProvider, Ping, ok_response
from taintwalk.llm.base import ContextOverflow, OfflineMiss
from taintwalk.llm.cache import DiskCache

SYS = "Reply only with JSON matching the schema."
SHORT = "int f(void);"
LONG = "int g(void);" + " x" * 100


class Tight(FakeProvider):
    """A provider whose preflight rejects any prompt over 80 characters."""

    def _preflight(self, system: str, user: str) -> None:
        if len(system) + len(user) > 80:
            raise ContextOverflow("tight: over budget")


def _shape(records):
    return [{k: v for k, v in r.items() if k != "wall_s"} for r in records]


def test_a_live_preflight_overflow_sends_nothing_and_caches_nothing(tmp_path):
    root = tmp_path / "c"
    live = Tight([ok_response()], cache=DiskCache(root))
    with pytest.raises(ContextOverflow):
        live.complete(SYS, LONG, Ping, binary_sha256=None)
    assert live.calls == [] and not list(root.rglob("*.json"))
    (rec,) = live.records
    assert rec["status"] == "raised" and rec["failure"] == "ContextOverflow" and rec["attempts"] == 0


def test_an_offline_replay_raises_and_records_the_same_overflow(tmp_path):
    cache = DiskCache(tmp_path / "c")
    live = Tight([ok_response()], cache=cache)
    with pytest.raises(ContextOverflow):
        live.complete(SYS, LONG, Ping, binary_sha256=None)
    replay = Tight([], cache=cache, offline=True)          # nothing scripted: any send would fail
    with pytest.raises(ContextOverflow):
        replay.complete(SYS, LONG, Ping, binary_sha256=None)
    assert replay.calls == []
    assert _shape(replay.records) == _shape(live.records)


def test_an_offline_miss_within_budget_is_still_a_miss(tmp_path):
    replay = Tight([], cache=DiskCache(tmp_path / "c"), offline=True)
    with pytest.raises(OfflineMiss):
        replay.complete(SYS, SHORT, Ping, binary_sha256=None)
    assert replay.calls == [] and replay.records == []