"""Retry vs repair (D-019). Retry = transport failure, same request, backoff.
Repair = content failure, a different request, at most once, never echoing model output.
Refusals, max_tokens, and config errors are terminal: neither retried nor repaired.
Raised outcomes are never cached, but they are recorded with the tokens they spent (D-032)."""
from __future__ import annotations

from pathlib import Path

import pytest

import taintwalk.llm.base as base_mod
from llm_fakes import FakeProvider, Ping, ok_response
from taintwalk.llm.base import (
    STOP_MAX_TOKENS,
    STOP_OVERFLOW,
    STOP_REFUSAL,
    ContextOverflow,
    ProviderConfigError,
    RetryExhausted,
    TransientError,
    Usage,
)
from taintwalk.llm.cache import DiskCache

SYSTEM = "You analyze decompiled C functions for data flow."
USER = "int f(int a) { return a + 1; }"


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


def _run(prov: FakeProvider):
    return prov.complete(SYSTEM, USER, Ping, binary_sha256=None)


# ---- repair ---------------------------------------------------------------------------

def test_invalid_json_is_repaired_once(tmp_path):
    prov = FakeProvider([ok_response(text="not json at all"), ok_response()], cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.ok and comp.repaired
    assert len(comp.attempts) == 2 and len(prov.calls) == 2
    assert comp.usage == Usage(input_tokens=80, output_tokens=40)
    repair_user = prov.calls[1]["user"]
    assert repair_user.startswith(USER) and "did not validate" in repair_user
    assert "not json at all" not in repair_user


def test_schema_violation_is_repaired_and_error_names_the_field(tmp_path):
    bad = ok_response(text='{"ok": true, "echo": "x", "count": 99}')
    prov = FakeProvider([bad, ok_response()], cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.ok and comp.repaired
    assert "count" in comp.attempts[0]["error"]
    assert "99" not in prov.calls[1]["user"]


def test_rejected_output_is_never_echoed_into_the_repair_prompt(tmp_path):
    bad = ok_response(text='{"ok": "ZZMARKER", "echo": "x", "count": 3}')
    prov = FakeProvider([bad, ok_response()], cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.ok
    assert "ZZMARKER" not in prov.calls[1]["user"]
    assert "ZZMARKER" not in comp.attempts[0]["error"]


def test_repair_prompt_passes_the_gate_again(tmp_path, monkeypatch):
    seen: list[str] = []
    real = base_mod.assert_clean

    def spy(text, binary_sha256=None, **kw):
        seen.append(text)
        return real(text, binary_sha256, **kw)

    monkeypatch.setattr(base_mod, "assert_clean", spy)
    prov = FakeProvider([ok_response(text="nope"), ok_response()], cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.ok and comp.repaired
    assert len(seen) == 2
    assert seen[1].endswith(prov.calls[1]["user"])


def test_two_failures_end_in_a_cached_schema_failure(tmp_path):
    prov = FakeProvider([ok_response(text="nope"), ok_response(text="still nope")],
                        cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.status == "failed" and comp.failure == "schema"
    assert len(comp.attempts) == 2 and len(prov.calls) == 2
    assert all(a["error"] for a in comp.attempts)
    assert len(_files(tmp_path)) == 1


# ---- terminal outcomes ----------------------------------------------------------------

def test_max_tokens_is_terminal_not_repaired(tmp_path):
    prov = FakeProvider([ok_response(text='{"ok": tr', stop_reason=STOP_MAX_TOKENS)],
                        cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.failure == "max_tokens" and not comp.repaired and len(prov.calls) == 1


def test_refusal_is_terminal_not_repaired(tmp_path):
    prov = FakeProvider([ok_response(text="", stop_reason=STOP_REFUSAL, category="cyber")],
                        cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.failure == "refusal:cyber" and not comp.repaired and len(prov.calls) == 1


def test_unknown_stop_reason_is_terminal(tmp_path):
    prov = FakeProvider([ok_response(stop_reason="pause_turn")], cache=DiskCache(tmp_path))
    comp = _run(prov)
    assert comp.failure == "stop:pause_turn" and len(prov.calls) == 1


def test_context_overflow_raises_and_is_not_cached(tmp_path):
    prov = FakeProvider([ok_response(text="", stop_reason=STOP_OVERFLOW)], cache=DiskCache(tmp_path))
    with pytest.raises(ContextOverflow):
        _run(prov)
    assert _files(tmp_path) == []  # never cached (D-019)
    (rec,) = prov.records  # but recorded with what the reply spent (D-032)
    assert rec["status"] == "raised" and rec["failure"] == "ContextOverflow"
    assert rec["usage"]["input_tokens"] == 40 and rec["usage"]["output_tokens"] == 20


# ---- retry ----------------------------------------------------------------------------

def test_transient_error_is_retried_not_repaired():
    prov = FakeProvider([TransientError("503"), ok_response()], cache=None)
    comp = _run(prov)
    assert comp.ok and not comp.repaired
    assert len(prov.calls) == 2 and len(comp.attempts) == 1  # a transport retry is not an attempt
    assert len(prov.sleeps) == 1 and prov.transient_retries == 1


def test_retry_after_is_honored_and_capped():
    prov = FakeProvider([TransientError("429", retry_after=7.0),
                         TransientError("429", retry_after=999.0),
                         ok_response()], cache=None)
    assert _run(prov).ok
    assert prov.sleeps == [7.0, 30.0]


def test_backoff_is_exponential_with_jitter():
    err = TransientError("503")
    prov = FakeProvider([err, err, err, err, ok_response()], cache=None, max_retries=4)
    assert _run(prov).ok
    assert prov.transient_retries == 4 and len(prov.sleeps) == 4
    for i, s in enumerate(prov.sleeps):
        assert 0.5 * 2 ** i <= s <= 2 ** i, (i, s)


def test_retry_exhaustion_raises_and_caches_nothing(tmp_path):
    err = TransientError("503")
    prov = FakeProvider([err, err, err], cache=DiskCache(tmp_path), max_retries=2)
    with pytest.raises(RetryExhausted):
        _run(prov)
    assert len(prov.calls) == 3 and len(prov.sleeps) == 2
    assert _files(tmp_path) == []  # never cached (D-019)
    (rec,) = prov.records  # recorded although no reply ever arrived (D-032)
    assert rec["status"] == "raised" and rec["failure"] == "RetryExhausted"
    assert rec["attempts"] == 0 and rec["usage"]["input_tokens"] == 0 and rec["usage"]["output_tokens"] == 0


def test_config_error_is_never_retried(tmp_path):
    prov = FakeProvider([ProviderConfigError("credit balance too low")], cache=DiskCache(tmp_path))
    with pytest.raises(ProviderConfigError):
        _run(prov)
    assert len(prov.calls) == 1 and prov.sleeps == []
    assert _files(tmp_path) == []