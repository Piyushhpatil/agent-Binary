"""Local Ollama backend (Phase 4; D-007, D-019). Standard-library HTTP only.

Findings from the Phase 4 spike (Ollama 0.34.4 on WSL2, RTX 4060 8 GB) that shape this file:

- Overflow behaviour depends on which runner serves the model. Some models get HTTP 400
  exceed_context_size_error. Others (qwen2.5-coder:7b, ornith:9b) have the FRONT of the
  prompt silently dropped: no error, and prompt_eval_count reports only what was kept.
  The API has no switch to disable truncation. Two defences, both loud:
    1. preflight: a conservative estimate (chars / CHARS_PER_TOKEN_FLOOR) must fit
       num_ctx - num_predict - TEMPLATE_OVERHEAD_TOKENS, or ContextOverflow before any I/O;
    2. post-check: more than MAX_CHARS_PER_TOKEN prompt characters per evaluated token
       means text went missing; the reply is reported as context_overflow, never cached.
  Both thresholds are provisional. Every reply records chars_per_token so Phase 5 can
  calibrate them on real decompiled pseudo-C.
- Thinking models think by default (ornith:9b spent 90 tokens on a 25-token answer).
  `think` is an explicit parameter and part of the cache key.
- temperature 0 plus a fixed seed gave identical output on repeat for every model tried.
- A tag is not the weights: `ollama pull` can move it. The digest is pinned in config and
  is part of identity(), so the cache key needs no network. It is verified against the
  server before the first request; a mismatch is fatal.
"""
from __future__ import annotations

import json
import math
import string
import urllib.error
import urllib.request
from typing import Any

from taintwalk.llm.base import (
    STOP_END,
    STOP_MAX_TOKENS,
    STOP_OVERFLOW,
    ContextOverflow,
    LLMProvider,
    ProviderConfigError,
    RawResponse,
    TransientError,
    Usage,
)
from taintwalk.llm.cache import DiskCache

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
CHARS_PER_TOKEN_FLOOR = 2.0      # preflight: assume text is this dense (overestimates tokens)
MAX_CHARS_PER_TOKEN = 8.0        # post-check: above this, prompt text went missing
TEMPLATE_OVERHEAD_TOKENS = 64    # chat template and role markers
_RETRYABLE_STATUS = frozenset({408, 429})
_MAX_ERROR_CHARS = 500
_DONE_MAP = {"stop": STOP_END, "length": STOP_MAX_TOKENS}
_HEX = frozenset(string.hexdigits.lower())


def _positive_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        params: dict[str, Any],
        *,
        cache: DiskCache | None,
        digest: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = 600.0,
        **kw: Any,
    ) -> None:
        params = dict(params)
        num_ctx, num_predict = params.get("num_ctx"), params.get("num_predict")
        if not (_positive_int(num_ctx) and _positive_int(num_predict)):
            raise ProviderConfigError("ollama params need positive integer num_ctx and num_predict")
        if num_predict + TEMPLATE_OVERHEAD_TOKENS >= num_ctx:
            raise ProviderConfigError("num_predict leaves no room for a prompt inside num_ctx")
        if not isinstance(digest, str) or len(digest) < 12 or not set(digest.lower()) <= _HEX:
            raise ProviderConfigError("ollama needs a pinned model digest: 12+ hex chars from `ollama list`")
        params.setdefault("think", None)
        params.setdefault("temperature", 0)
        params.setdefault("seed", 0)
        super().__init__(model, params, cache=cache, **kw)
        self.digest = digest.lower()
        self.base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._verified = False

    # ---- identity and budget --------------------------------------------------------

    def identity(self) -> dict[str, Any]:
        ident = super().identity()
        ident["digest"] = self.digest
        return ident

    @property
    def prompt_budget(self) -> int:
        return self.params["num_ctx"] - self.params["num_predict"] - TEMPLATE_OVERHEAD_TOKENS

    def _preflight(self, system: str, user: str) -> None:
        estimate = math.ceil((len(system) + len(user)) / CHARS_PER_TOKEN_FLOOR)
        if estimate > self.prompt_budget:
            raise ContextOverflow(
                f"ollama preflight: ~{estimate} prompt tokens (conservative estimate) exceeds "
                f"budget {self.prompt_budget} (num_ctx {self.params['num_ctx']}, "
                f"num_predict {self.params['num_predict']})"
            )

    # ---- HTTP -----------------------------------------------------------------------

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")[:_MAX_ERROR_CHARS]
            if e.code == 400 and "exceed_context_size" in text:
                raise ContextOverflow(f"ollama server: {text}") from e
            if e.code in _RETRYABLE_STATUS or e.code >= 500:
                raise TransientError(f"ollama HTTP {e.code}: {text}") from e
            raise ProviderConfigError(f"ollama HTTP {e.code}: {text}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            raise TransientError(
                f"ollama unreachable at {self.base_url} ({e}); is the service running?"
            ) from e
        except json.JSONDecodeError as e:
            raise ProviderConfigError(f"ollama returned non-JSON on {path}: {e.msg}") from e

    def _verify_model(self) -> None:
        if self._verified:
            return
        models = self._call("GET", "/api/tags").get("models", [])
        m = next((x for x in models if self.model in (x.get("name"), x.get("model"))), None)
        if m is None:
            raise ProviderConfigError(f"ollama model {self.model} is not pulled (ollama pull {self.model})")
        got = str(m.get("digest", "")).lower()
        if not got.startswith(self.digest):
            raise ProviderConfigError(
                f"ollama model {self.model} digest {got[:12]} != pinned {self.digest[:12]}; "
                f"the tag moved. Re-pin it in config deliberately."
            )
        self._verified = True

    def residency(self) -> dict[str, Any]:
        """Is the model loaded, and what share of it sits in VRAM (from /api/ps)?"""
        for m in self._call("GET", "/api/ps").get("models", []):
            if self.model in (m.get("name"), m.get("model")):
                size, vram = m.get("size") or 0, m.get("size_vram") or 0
                return {
                    "loaded": True,
                    "gpu_pct": round(100 * vram / size) if size else 0,
                    "context_length": m.get("context_length"),
                }
        return {"loaded": False}

    # ---- send -----------------------------------------------------------------------

    def _send(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        self._verify_model()
        p = self.params
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "format": schema,
            "options": {
                "num_ctx": p["num_ctx"],
                "num_predict": p["num_predict"],
                "temperature": p["temperature"],
                "seed": p["seed"],
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if p["think"] is not None:
            body["think"] = p["think"]
        r = self._call("POST", "/api/chat", body)
        return self._normalize(r, prompt_chars=len(system) + len(user))

    def _normalize(self, r: dict[str, Any], prompt_chars: int) -> RawResponse:
        msg = r.get("message") or {}
        evaluated = r.get("prompt_eval_count")
        if evaluated is None:
            raise ProviderConfigError(
                "ollama reply lacks prompt_eval_count; cannot rule out silent prompt truncation"
            )
        cached = r.get("prompt_eval_cached_count") or 0
        prompt_tokens = evaluated + cached
        ratio = prompt_chars / max(prompt_tokens, 1)
        detail: dict[str, Any] = {
            "prompt_tokens": prompt_tokens,
            "chars_per_token": round(ratio, 2),
            "done_reason": r.get("done_reason"),
        }
        if msg.get("thinking"):
            detail["thinking_chars"] = len(msg["thinking"])
        if ratio > MAX_CHARS_PER_TOKEN:
            stop = STOP_OVERFLOW
        else:
            reason = r.get("done_reason") or "unknown"
            stop = _DONE_MAP.get(reason, reason)
        return RawResponse(
            text=msg.get("content", ""),
            stop_reason=stop,
            usage=Usage(
                input_tokens=evaluated,
                output_tokens=r.get("eval_count") or 0,
                provider_cached_input_tokens=cached,
            ),
            model=r.get("model", self.model),
            request_id=None,
            detail=detail,
        )