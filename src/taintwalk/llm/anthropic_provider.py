"""Anthropic Messages API backend (Phase 4; D-007, D-019).

Verified against anthropic 1.8.0 in the Phase 4 spike:
- messages.create() accepts output_config (format + effort) and thinking. It no longer
  accepts temperature/top_p/top_k, so the cloud model cannot be asked for determinism.
  Replay determinism comes from the disk cache (I2), not from sampling settings.
- A billing problem arrives as HTTP 400 invalid_request_error: fatal, never retried.

Structured output uses output_config.format (constrained decoding). The schema goes
through the SDK's transform_schema(), which strips keywords the API does not support
(minimum, maximum, ...) and closes every object. base.complete() still validates the
reply against the full pydantic model, so stripped constraints are enforced client-side.

The SDK's own retries are disabled (max_retries=0). base.complete() owns the single,
logged, tested retry policy; two stacked retry layers multiply and hide rate limiting.

The SDK version is part of identity(): transform_schema() is SDK code, so a different
SDK can send a different schema for the same prompt. An SDK upgrade invalidates the cache.
"""
from __future__ import annotations

import copy
import os
from typing import Any

import anthropic
from anthropic import transform_schema

from taintwalk.llm.base import (
    STOP_END,
    STOP_MAX_TOKENS,
    STOP_OVERFLOW,
    STOP_REFUSAL,
    LLMProvider,
    ProviderConfigError,
    RawResponse,
    TransientError,
    Usage,
)
from taintwalk.llm.cache import DiskCache

API_KEY_ENV = "ANTHROPIC_API_KEY"
_STOP_MAP = {
    "end_turn": STOP_END,
    "max_tokens": STOP_MAX_TOKENS,
    "refusal": STOP_REFUSAL,
    "model_context_window_exceeded": STOP_OVERFLOW,
}
_RETRYABLE_STATUS = frozenset({408, 409, 429})
_MAX_ERROR_CHARS = 500


def _retry_after(e: anthropic.APIStatusError) -> float | None:
    try:
        value = e.response.headers.get("retry-after")
        return float(value) if value is not None else None
    except (AttributeError, TypeError, ValueError):
        return None


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self,
        model: str,
        params: dict[str, Any],
        *,
        cache: DiskCache | None,
        client: anthropic.Anthropic | None = None,
        timeout_s: float = 120.0,
        **kw: Any,
    ) -> None:
        params = dict(params)
        max_tokens = params.get("max_tokens")
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise ProviderConfigError("anthropic params need a positive integer max_tokens")
        params.setdefault("thinking", None)
        params.setdefault("effort", None)
        super().__init__(model, params, cache=cache, **kw)
        self._client = client
        self._timeout_s = timeout_s

    def identity(self) -> dict[str, Any]:
        ident = super().identity()
        ident["sdk"] = anthropic.__version__
        return ident

    def _get_client(self) -> anthropic.Anthropic:
        # Created lazily: a run served entirely from the cache needs no key.
        if self._client is None:
            key = os.environ.get(API_KEY_ENV)
            if not key:
                raise ProviderConfigError(
                    f"{API_KEY_ENV} is not set (source ~/.config/taintwalk/secrets.env)"
                )
            self._client = anthropic.Anthropic(api_key=key, max_retries=0, timeout=self._timeout_s)
        return self._client

    def _request(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        output_config: dict[str, Any] = {
            "format": {"type": "json_schema", "schema": transform_schema(copy.deepcopy(schema))}
        }
        if self.params["effort"] is not None:
            output_config["effort"] = self.params["effort"]
        req: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.params["max_tokens"],
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": output_config,
        }
        if self.params["thinking"] is not None:
            req["thinking"] = self.params["thinking"]
        return req

    def _send(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        client = self._get_client()
        try:
            r = client.messages.create(**self._request(system, user, schema))
        except (anthropic.APITimeoutError, anthropic.APIConnectionError) as e:
            raise TransientError(f"anthropic connection: {type(e).__name__}") from e
        except anthropic.APIStatusError as e:
            msg = f"anthropic HTTP {e.status_code}: {str(e)[:_MAX_ERROR_CHARS]}"
            if e.status_code in _RETRYABLE_STATUS or e.status_code >= 500:
                raise TransientError(msg, retry_after=_retry_after(e)) from e
            raise ProviderConfigError(msg) from e
        return self._normalize(r)

    @staticmethod
    def _normalize(r: Any) -> RawResponse:
        text = "".join(
            getattr(b, "text", "") for b in (r.content or []) if getattr(b, "type", None) == "text"
        )
        stop = _STOP_MAP.get(r.stop_reason, r.stop_reason or "unknown")
        u = r.usage
        details = getattr(u, "output_tokens_details", None)
        thinking = (getattr(details, "thinking_tokens", 0) or 0) if details is not None else 0
        usage = Usage(
            input_tokens=u.input_tokens or 0,
            output_tokens=u.output_tokens or 0,
            thinking_tokens=thinking,
            provider_cached_input_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
        )
        detail: dict[str, Any] = {}
        stop_details = getattr(r, "stop_details", None)
        if stop_details is not None:
            category = (
                stop_details.get("category") if isinstance(stop_details, dict)
                else getattr(stop_details, "category", None)
            )
            detail["category"] = category
        return RawResponse(
            text=text,
            stop_reason=stop,
            usage=usage,
            model=r.model,
            request_id=getattr(r, "_request_id", None),
            detail=detail,
        )