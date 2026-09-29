"""Ollama backend against a local fake Ollama server: stdlib HTTP end to end, with no GPU
and no model. Proves the request shape, the digest pin, cache-only replay with the
server off, and both overflow defences against the silent front-truncation found in the
Phase 4 spike, including on warm-cache replies (D-022) and at the calibrated threshold (D-024)."""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from llm_fakes import GOOD_TEXT, Ping
from taintwalk.llm.base import ContextOverflow, ProviderConfigError, RetryExhausted, Usage
from taintwalk.llm.cache import DiskCache
from taintwalk.llm.ollama_provider import OllamaProvider

MODEL = "ornith:9b"
DIGEST = "a75697c14589"
FULL_DIGEST = DIGEST + "0" * 52
SYSTEM = "You analyze decompiled C functions for data flow."
USER = "int f(int a) { return a + 1; }"
PARAMS = {"num_ctx": 16384, "num_predict": 1024}


def chat_ok(content: str = GOOD_TEXT, prompt_eval_count: int = 40, eval_count: int = 20,
            done_reason: str = "stop", **extra: Any):
    body = {
        "model": MODEL,
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": done_reason,
        "prompt_eval_count": prompt_eval_count,
        "eval_count": eval_count,
    }
    body.update(extra)
    return (200, body)


def http_error(status: int, message: str):
    return (status, {"error": message})


def _handler(state):
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            state.requests.append({"method": "GET", "path": self.path})
            if self.path == "/api/tags":
                self._reply(200, {"models": state.tags})
            elif self.path == "/api/ps":
                self._reply(200, {"models": state.ps})
            else:
                self._reply(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            state.requests.append({"method": "POST", "path": self.path, "body": body})
            if state.script:
                status, payload = state.script.pop(0)
            else:
                status, payload = http_error(500, "fake server script exhausted")
            self._reply(status, payload)

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture
def server():
    state = SimpleNamespace(
        script=[], requests=[], ps=[],
        tags=[{"name": MODEL, "model": MODEL, "digest": FULL_DIGEST}],
    )
    srv = HTTPServer(("127.0.0.1", 0), _handler(state))
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    state.base_url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()
    srv.server_close()


def provider(base_url: str, tmp_path: Path, params: dict[str, Any] | None = None,
             digest: str = DIGEST, **kw: Any) -> OllamaProvider:
    sleeps: list[float] = []
    p = OllamaProvider(MODEL, {**PARAMS, **(params or {})}, cache=DiskCache(tmp_path / "c"),
                       digest=digest, base_url=base_url, timeout_s=5.0,
                       sleep=sleeps.append, **kw)
    p.sleeps = sleeps
    return p


def run(p: OllamaProvider, user: str = USER):
    return p.complete(SYSTEM, user, Ping, binary_sha256=None)


def chats(state) -> list[dict[str, Any]]:
    return [r for r in state.requests if r["method"] == "POST"]


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()] if root.exists() else []


def _raised(p: OllamaProvider) -> dict[str, Any]:
    """D-032: a raised call is never cached, but it leaves exactly one record with its tokens."""
    (rec,) = p.records
    assert rec["status"] == "raised" and rec["failure"] == "ContextOverflow"
    return rec


# ---- request shape and cache ----------------------------------------------------------

def test_success_and_request_shape(server, tmp_path):
    server.script = [chat_ok()]
    comp = run(provider(server.base_url, tmp_path))
    assert comp.ok and comp.data == {"ok": True, "echo": "taintwalk", "count": 3}
    assert [(r["method"], r["path"]) for r in server.requests] == [("GET", "/api/tags"), ("POST", "/api/chat")]
    body = chats(server)[0]["body"]
    assert body["model"] == MODEL and body["stream"] is False
    assert body["format"] == Ping.model_json_schema()
    assert body["options"] == {"num_ctx": 16384, "num_predict": 1024, "temperature": 0, "seed": 0}
    assert body["messages"] == [{"role": "system", "content": SYSTEM}, {"role": "user", "content": USER}]
    assert "think" not in body


def test_think_is_sent_only_when_configured(server, tmp_path):
    server.script = [chat_ok()]
    run(provider(server.base_url, tmp_path, params={"think": False}))
    assert chats(server)[0]["body"]["think"] is False


def test_second_call_is_a_cache_hit_with_no_request_at_all(server, tmp_path):
    server.script = [chat_ok()]
    run(provider(server.base_url, tmp_path))
    n = len(server.requests)
    comp = run(provider(server.base_url, tmp_path))
    assert comp.cache_hit and comp.usage == Usage()
    assert len(server.requests) == n  # not even /api/tags: the digest is pinned, not fetched


# ---- digest pin -----------------------------------------------------------------------

def test_digest_mismatch_is_fatal_before_any_chat(server, tmp_path):
    p = provider(server.base_url, tmp_path, digest="deadbeef0000")
    with pytest.raises(ProviderConfigError, match="digest"):
        run(p)
    assert chats(server) == []


def test_model_not_pulled_is_fatal(server, tmp_path):
    server.tags = []
    with pytest.raises(ProviderConfigError, match="not pulled"):
        run(provider(server.base_url, tmp_path))
    assert chats(server) == []


# ---- overflow defences ----------------------------------------------------------------

def test_preflight_rejects_an_oversized_prompt_with_no_request(server, tmp_path):
    p = provider(server.base_url, tmp_path, params={"num_ctx": 1024, "num_predict": 256})
    with pytest.raises(ContextOverflow, match="preflight"):
        run(p, user="x" * 2000)
    assert server.requests == []


def test_silent_truncation_is_detected_and_not_cached(server, tmp_path):
    big = "int x;\n" * 600  # 4200 chars: passes preflight for num_ctx 16384
    server.script = [chat_ok(prompt_eval_count=100)]  # ~42 chars/token: text went missing
    p = provider(server.base_url, tmp_path)
    with pytest.raises(ContextOverflow):
        run(p, user=big)
    assert _files(tmp_path / "c") == []
    rec = _raised(p)
    assert rec["usage"]["input_tokens"] == 100 and rec["usage"]["output_tokens"] == 20


def test_truncation_is_detected_on_a_warm_cache_reply(server, tmp_path):
    # D-022: prompt_eval_cached_count is a subset of prompt_eval_count. Here ~4250 chars
    # arrive as 500 evaluated tokens (~8.5 chars/token), so text went missing. The old
    # formula divided by 500 + 495 (~4.3 chars/token) and would have let this through.
    big = "int x;\n" * 600
    server.script = [chat_ok(prompt_eval_count=500, prompt_eval_cached_count=495)]
    p = provider(server.base_url, tmp_path)
    with pytest.raises(ContextOverflow):
        run(p, user=big)
    assert _files(tmp_path / "c") == []
    rec = _raised(p)
    assert rec["usage"]["input_tokens"] == 500 and rec["usage"]["provider_cached_input_tokens"] == 495


def test_warm_cache_reply_counts_prompt_tokens_once(server, tmp_path):
    # A healthy warm reply: ~2.6 chars/token, as measured in the Phase 5 spike.
    big = "int x;\n" * 600
    server.script = [chat_ok(prompt_eval_count=1640, prompt_eval_cached_count=1636)]
    comp = run(provider(server.base_url, tmp_path), user=big)
    assert comp.ok
    detail = comp.attempts[0]["detail"]
    assert detail["prompt_tokens"] == 1640 and detail["cached_prompt_tokens"] == 1636
    assert detail["chars_per_token"] == round((len(SYSTEM) + len(big)) / 1640, 2)


def test_moderate_truncation_is_detected_at_the_calibrated_threshold(server, tmp_path):
    # D-024: real prompts run 3.1-3.4 chars/token. ~5.3 chars/token means about 40% of the
    # text is missing: caught at 5.0, missed at the old 8.0.
    big = "int x;\n" * 600
    server.script = [chat_ok(prompt_eval_count=800)]
    p = provider(server.base_url, tmp_path)
    with pytest.raises(ContextOverflow):
        run(p, user=big)
    assert _files(tmp_path / "c") == []
    rec = _raised(p)
    assert rec["usage"]["input_tokens"] == 800 and rec["usage"]["output_tokens"] == 20


def test_server_context_error_maps_to_overflow_without_retry(server, tmp_path):
    server.script = [http_error(400, '{"error":{"type":"exceed_context_size_error","n_ctx":1024}}')]
    p = provider(server.base_url, tmp_path)
    with pytest.raises(ContextOverflow):
        run(p)
    assert len(chats(server)) == 1 and p.sleeps == []


# ---- stop reasons, retries, fail-closed -----------------------------------------------

def test_length_is_terminal_max_tokens(server, tmp_path):
    server.script = [chat_ok(content='{"ok": tr', done_reason="length")]
    comp = run(provider(server.base_url, tmp_path))
    assert comp.failure == "max_tokens" and len(chats(server)) == 1


def test_5xx_is_retried(server, tmp_path):
    server.script = [http_error(500, "runner crashed"), chat_ok()]
    p = provider(server.base_url, tmp_path)
    assert run(p).ok
    assert len(chats(server)) == 2 and len(p.sleeps) == 1


def test_unreachable_server_exhausts_retries(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    p = provider(f"http://127.0.0.1:{port}", tmp_path, max_retries=1)
    with pytest.raises(RetryExhausted, match="unreachable"):
        run(p)
    assert len(p.sleeps) == 1


def test_missing_prompt_eval_count_fails_closed(server, tmp_path):
    status, body = chat_ok()
    del body["prompt_eval_count"]
    server.script = [(status, body)]
    with pytest.raises(ProviderConfigError, match="prompt_eval_count"):
        run(provider(server.base_url, tmp_path))


def test_usage_maps_prompt_and_eval_counts(server, tmp_path):
    server.script = [chat_ok(prompt_eval_count=41, eval_count=25, prompt_eval_cached_count=5)]
    comp = run(provider(server.base_url, tmp_path))
    assert comp.usage == Usage(input_tokens=41, output_tokens=25, provider_cached_input_tokens=5)
    assert comp.attempts[0]["detail"]["prompt_tokens"] == 41  # D-022: cached is not added


# ---- residency and construction -------------------------------------------------------

def test_residency_reports_gpu_share(server, tmp_path):
    server.ps = [{"name": MODEL, "model": MODEL, "size": 100, "size_vram": 76, "context_length": 16384}]
    assert provider(server.base_url, tmp_path).residency() == {
        "loaded": True, "gpu_pct": 76, "context_length": 16384,
    }


def test_residency_when_not_loaded(server, tmp_path):
    assert provider(server.base_url, tmp_path).residency() == {"loaded": False}


def test_identity_includes_pinned_digest():
    p = OllamaProvider(MODEL, PARAMS, cache=None, digest=DIGEST.upper())
    ident = p.identity()
    assert ident["provider"] == "ollama" and ident["model"] == MODEL and ident["digest"] == DIGEST
    assert ident["params"] == {**PARAMS, "think": None, "temperature": 0, "seed": 0}


@pytest.mark.parametrize(
    "params,digest",
    [
        ({"num_predict": 1024}, DIGEST),
        ({"num_ctx": 1024, "num_predict": 1000}, DIGEST),
        (PARAMS, ""),
        (PARAMS, "not-a-digest"),
    ],
    ids=["no-num_ctx", "no-room-for-prompt", "empty-digest", "non-hex-digest"],
)
def test_bad_construction_is_rejected(params, digest):
    with pytest.raises(ProviderConfigError):
        OllamaProvider(MODEL, params, cache=None, digest=digest)