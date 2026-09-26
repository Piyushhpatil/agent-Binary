"""Anthropic backend against a local fake API server: the real SDK, real HTTP, and the
SDK's real exception classes, with no network and no credits. Proves the request shape
(no sampling params, transformed schema) and the error taxonomy (retry vs fatal)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import Any

import anthropic
import pytest

from llm_fakes import GOOD_TEXT, Ping
from taintwalk.llm.anthropic_provider import AnthropicProvider
from taintwalk.llm.base import ContextOverflow, ProviderConfigError, RetryExhausted, Usage
from taintwalk.llm.cache import DiskCache

MODEL = "claude-haiku-4-5-20251001"
SYSTEM = "You analyze decompiled C functions for data flow."
USER = "int f(int a) { return a + 1; }"


def message(text: str = GOOD_TEXT, stop_reason: str = "end_turn",
            input_tokens: int = 300, output_tokens: int = 20, **extra: Any):
    body = {
        "id": "msg_test", "type": "message", "role": "assistant", "model": MODEL,
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }
    body.update(extra)
    return (200, {}, body)


def error(status: int, etype: str, msg: str, headers: dict[str, str] | None = None):
    return (status, headers or {}, {"type": "error", "error": {"type": etype, "message": msg}})


def _handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            state.requests.append({"path": self.path, "body": json.loads(self.rfile.read(n) or b"{}")})
            if state.script:
                status, headers, payload = state.script.pop(0)
            else:
                status, headers, payload = error(500, "api_error", "fake server script exhausted")
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture
def api():
    state = SimpleNamespace(script=[], requests=[])
    server = HTTPServer(("127.0.0.1", 0), _handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.client = anthropic.Anthropic(
        api_key="test-key",
        base_url=f"http://127.0.0.1:{server.server_address[1]}",
        max_retries=0,
        timeout=5.0,
    )
    yield state
    server.shutdown()
    server.server_close()


def provider(api, tmp_path, params: dict[str, Any] | None = None, **kw: Any) -> AnthropicProvider:
    sleeps: list[float] = []
    p = AnthropicProvider(MODEL, {"max_tokens": 256, **(params or {})},
                          cache=DiskCache(tmp_path / "c"), client=api.client,
                          sleep=sleeps.append, **kw)
    p.sleeps = sleeps
    return p


def run(p: AnthropicProvider):
    return p.complete(SYSTEM, USER, Ping, binary_sha256=None)


def _keys(obj: Any) -> set[str]:
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in _keys(v)}
    if isinstance(obj, list):
        return {k for v in obj for k in _keys(v)}
    return set()


# ---- request shape --------------------------------------------------------------------

def test_success_and_request_shape(api, tmp_path):
    api.script = [message()]
    comp = run(provider(api, tmp_path))
    assert comp.ok and comp.data == {"ok": True, "echo": "taintwalk", "count": 3}
    assert comp.usage == Usage(input_tokens=300, output_tokens=20)

    (req,) = api.requests
    assert req["path"] == "/v1/messages"
    body = req["body"]
    assert body["model"] == MODEL and body["max_tokens"] == 256 and body["system"] == SYSTEM
    assert body["messages"] == [{"role": "user", "content": USER}]
    fmt = body["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    assert fmt["schema"].get("additionalProperties") is False
    assert not {"minimum", "maximum"} & _keys(fmt["schema"]), "transform_schema did not run"
    for absent in ("temperature", "top_p", "top_k", "thinking"):
        assert absent not in body


def test_thinking_and_effort_are_sent_only_when_configured(api, tmp_path):
    api.script = [message()]
    run(provider(api, tmp_path, params={"thinking": {"type": "disabled"}, "effort": "low"}))
    body = api.requests[0]["body"]
    assert body["thinking"] == {"type": "disabled"}
    assert body["output_config"]["effort"] == "low"


def test_second_call_is_a_cache_hit_with_no_request(api, tmp_path):
    api.script = [message()]
    run(provider(api, tmp_path))
    comp = run(provider(api, tmp_path))
    assert comp.cache_hit and comp.usage == Usage()
    assert len(api.requests) == 1


# ---- error taxonomy -------------------------------------------------------------------

def test_rate_limit_is_retried_with_retry_after(api, tmp_path):
    api.script = [error(429, "rate_limit_error", "slow down", {"retry-after": "3"}), message()]
    p = provider(api, tmp_path)
    assert run(p).ok
    assert p.sleeps == [3.0] and len(api.requests) == 2


def test_overloaded_529_is_retried(api, tmp_path):
    api.script = [error(529, "overloaded_error", "overloaded"), message()]
    p = provider(api, tmp_path)
    assert run(p).ok and len(api.requests) == 2


def test_persistent_5xx_exhausts_retries(api, tmp_path):
    api.script = [error(500, "api_error", "boom") for _ in range(3)]
    p = provider(api, tmp_path, max_retries=2)
    with pytest.raises(RetryExhausted):
        run(p)
    assert len(api.requests) == 3 and len(p.sleeps) == 2


def test_billing_400_is_fatal_and_not_retried(api, tmp_path):
    api.script = [error(400, "invalid_request_error", "Your credit balance is too low")]
    p = provider(api, tmp_path)
    with pytest.raises(ProviderConfigError, match="credit balance"):
        run(p)
    assert len(api.requests) == 1 and p.sleeps == []


def test_unknown_model_404_is_fatal(api, tmp_path):
    api.script = [error(404, "not_found_error", "model: claude-does-not-exist")]
    p = provider(api, tmp_path)
    with pytest.raises(ProviderConfigError):
        run(p)
    assert len(api.requests) == 1


# ---- stop reasons ---------------------------------------------------------------------

def test_refusal_maps_to_terminal_failure_with_category(api, tmp_path):
    api.script = [message(text="", stop_reason="refusal",
                          stop_details={"type": "refusal", "category": "cyber", "explanation": None})]
    comp = run(provider(api, tmp_path))
    assert comp.failure == "refusal:cyber" and len(api.requests) == 1


def test_context_window_exceeded_raises(api, tmp_path):
    api.script = [message(text="", stop_reason="model_context_window_exceeded")]
    with pytest.raises(ContextOverflow):
        run(provider(api, tmp_path))


def test_max_tokens_is_terminal(api, tmp_path):
    api.script = [message(text='{"ok": tr', stop_reason="max_tokens")]
    comp = run(provider(api, tmp_path))
    assert comp.failure == "max_tokens" and len(api.requests) == 1


# ---- construction ---------------------------------------------------------------------

def test_missing_api_key_fails_on_send_not_on_construction(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = AnthropicProvider(MODEL, {"max_tokens": 256}, cache=DiskCache(tmp_path / "c"))
    with pytest.raises(ProviderConfigError, match="ANTHROPIC_API_KEY"):
        run(p)


def test_identity_pins_model_params_and_sdk_version():
    p = AnthropicProvider(MODEL, {"max_tokens": 256}, cache=None)
    ident = p.identity()
    assert ident["provider"] == "anthropic" and ident["model"] == MODEL
    assert ident["sdk"] == anthropic.__version__
    assert ident["params"] == {"max_tokens": 256, "thinking": None, "effort": None}


@pytest.mark.parametrize("params", [{}, {"max_tokens": 0}, {"max_tokens": "256"}, {"max_tokens": True}])
def test_bad_max_tokens_is_rejected(params):
    with pytest.raises(ProviderConfigError):
        AnthropicProvider(MODEL, params, cache=None)