"""Provider-independent LLM call path (Phase 4; D-017, D-019).

Every provider inherits complete(), which runs one pipeline for every call:

    leak gate -> cache lookup -> preflight -> send (transport retry)
              -> parse + validate -> at most one repair -> cache store -> record

Providers implement _send() and may override identity() and _preflight(). The gate
and the cache are project invariants, not provider features, so no provider can skip
them: complete() is defined once, here.

Retry and repair are different operations:
- retry:  a transport failure (rate limit, overload, 5xx, timeout, connection). The
          same request again, with exponential backoff and jitter. Only a
          TransientError raised by _send() triggers it.
- repair: a content failure (invalid JSON, schema violation). A different request: the
          original user prompt plus the validation errors, at most REPAIR_LIMIT times.
          The model's rejected output is NOT echoed back, so the gate never judges
          model-generated text, and the error text never quotes input values.

Terminal outcomes (ok, schema failure, max_tokens, refusal) are cached, so an
unchanged re-run costs zero tokens and replays identically (I2, I3). Transient errors
and context overflow are raised, never cached.

A raised LLMError (context overflow, retry exhaustion, a fatal provider error) is still
recorded, as status "raised" with the tokens the call had already spent, so usage
accounting never drops a partial call (D-032). Only the exception's type name is
recorded, never its message.

Offline mode (replay only, D-032): a cache miss raises OfflineMiss right after the cache
lookup and the local preflight, before any network I/O. A replay is then free by construction,
not merely because a token count happened to come back zero. A prompt the preflight rejects
raises ContextOverflow and is recorded exactly as it was live (D-041): an overflow is never
cached, so a replay has to re-derive it.

A LeakError is never caught here. Its message holds ground-truth text; it must not
reach a prompt, the repair loop, the cache, or a log line.
"""
from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, astuple, dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from taintwalk.llm.cache import CACHE_FORMAT, CacheCorrupt, DiskCache, cache_key
from taintwalk.util.leakcheck import assert_clean

REPAIR_LIMIT = 1
MAX_ERROR_CHARS = 1500

# Normalized stop reasons. Each provider maps its own values onto these.
STOP_END = "end"
STOP_MAX_TOKENS = "max_tokens"
STOP_REFUSAL = "refusal"
STOP_OVERFLOW = "context_overflow"

REPAIR_TEMPLATE = (
    "{user}\n\n"
    "Your previous reply did not validate against the required JSON schema:\n"
    "{errors}\n"
    "Reply again with only a JSON object that satisfies the schema."
)


class LLMError(RuntimeError):
    """Base class for every error raised by the llm package."""


class ProviderConfigError(LLMError):
    """Fatal, never retried: missing key, auth, billing, unknown model, rejected request."""


class TransientError(LLMError):
    """Retryable transport failure: rate limit, overload, 5xx, timeout, connection."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class RetryExhausted(LLMError):
    """A transient failure persisted through every retry."""


class ContextOverflow(LLMError):
    """The prompt does not fit the model's context window. Never retried, never cached."""


class OfflineMiss(LLMError):
    """Offline mode (replay only) found no cached reply. Raised before any network I/O."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0               # already included in output_tokens where reported
    provider_cached_input_tokens: int = 0  # the provider's prompt cache, not our disk cache

    def __add__(self, other: Usage) -> Usage:
        return Usage(*(a + b for a, b in zip(astuple(self), astuple(other))))

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class RawResponse:
    """What a provider's _send() returns: one model reply, already normalized."""

    text: str
    stop_reason: str
    usage: Usage
    model: str
    request_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Completion:
    """What complete() returns. `usage` is what THIS call spent: zero on a cache hit."""

    key: str
    provider: str
    model: str
    status: str                  # "ok" | "failed"
    failure: str | None          # "schema" | "max_tokens" | "refusal:<category>" | "stop:<reason>"
    data: dict[str, Any] | None
    raw_text: str
    attempts: tuple[dict[str, Any], ...]
    usage: Usage
    cache_hit: bool
    repaired: bool

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_entry(self, identity: dict[str, Any]) -> dict[str, Any]:
        return {
            "format": CACHE_FORMAT,
            "key": self.key,
            "identity": identity,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "failure": self.failure,
            "data": self.data,
            "raw_text": self.raw_text,
            "attempts": list(self.attempts),
            "usage": asdict(self.usage),
            "repaired": self.repaired,
        }

    @classmethod
    def from_entry(cls, entry: dict[str, Any]) -> Completion:
        try:
            return cls(
                key=entry["key"],
                provider=entry["provider"],
                model=entry["model"],
                status=entry["status"],
                failure=entry["failure"],
                data=entry["data"],
                raw_text=entry["raw_text"],
                attempts=tuple(entry["attempts"]),
                usage=Usage(),
                cache_hit=True,
                repaired=entry["repaired"],
            )
        except (KeyError, TypeError) as e:
            raise CacheCorrupt(f"cache entry {entry.get('key', '?')}: missing or bad field {e}") from e

    def record(self, wall_s: float) -> dict[str, Any]:
        return {
            "key": self.key,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "failure": self.failure,
            "cache_hit": self.cache_hit,
            "repaired": self.repaired,
            "attempts": len(self.attempts),
            "usage": asdict(self.usage),
            "wall_s": round(wall_s, 3),
        }


def _validation_summary(e: ValidationError) -> str:
    """Field locations and messages only. Never input values: they are model output."""
    lines = []
    for err in e.errors(include_url=False, include_input=False, include_context=False):
        loc = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
        lines.append(f"- {loc}: {err.get('msg', 'invalid')}")
    return "\n".join(lines)[:MAX_ERROR_CHARS]


class LLMProvider(ABC):
    """One backend. Subclasses set `name` and implement _send()."""

    name: str = ""

    def __init__(
        self,
        model: str,
        params: dict[str, Any] | None = None,
        *,
        cache: DiskCache | None,
        offline: bool = False,
        max_retries: int = 4,
        backoff_base_s: float = 1.0,
        backoff_cap_s: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if not self.name:
            raise TypeError(f"{type(self).__name__} must set a class-level `name`")
        if offline and cache is None:
            raise ProviderConfigError("offline mode replays from the disk cache; it needs one")
        self.model = model
        self.params = dict(params or {})
        self.cache = cache
        self.offline = offline
        self.max_retries = max_retries
        self.backoff_base_s = backoff_base_s
        self.backoff_cap_s = backoff_cap_s
        self._sleep = sleep
        self._rng = rng if rng is not None else random.Random()
        self.records: list[dict[str, Any]] = []
        self.transient_retries = 0

    # ---- provider hooks -------------------------------------------------------------

    @abstractmethod
    def _send(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        """One request to the backend. Raise TransientError for retryable transport
        failures and ProviderConfigError for fatal ones. Never catch LeakError."""

    def identity(self) -> dict[str, Any]:
        """Everything besides the prompt that determines the output. Part of the cache key.
        Providers extend this with a model version or digest when one exists."""
        return {"provider": self.name, "model": self.model, "params": self.params}

    def _preflight(self, system: str, user: str) -> None:
        """Raise ContextOverflow before any network I/O if the prompt cannot fit."""

    # ---- the pipeline ---------------------------------------------------------------

    @property
    def token_usage(self) -> Usage:
        """Tokens spent by this provider instance, raised calls included. Cache hits contribute zero."""
        total = Usage()
        for r in self.records:
            total = total + Usage(**r["usage"])
        return total

    def complete(
        self,
        system: str,
        user: str,
        schema: type[BaseModel],
        *,
        binary_sha256: str | None,
        retry_failed: bool = False,
    ) -> Completion:
        """One structured completion.

        binary_sha256 has no default on purpose. Pass the analyzed binary's sha256 for
        the full gate (static + per-binary name layer), or None explicitly for the
        static layer only.
        """
        if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
            raise TypeError("schema must be a pydantic BaseModel subclass")
        t0 = time.monotonic()

        # 1. Leak gate, before any cache or network I/O (D-017).
        self._gate(system, user, binary_sha256)

        # 2. Cache lookup.
        schema_json = schema.model_json_schema()
        key = cache_key(self.identity(), system, user, schema_json)
        if self.cache is not None:
            entry = self.cache.get(key)
            if entry is not None and not (retry_failed and entry.get("status") == "failed"):
                hit = Completion.from_entry(entry)
                self.records.append(hit.record(time.monotonic() - t0))
                return hit

        # 2b. Offline mode (replay only, D-032): a miss stops here, before any network I/O. The local
        #     preflight runs first (D-041): an overflow is never cached, so without it a live run's
        #     overflow could not replay. It is recorded exactly as the live path records it.
        if self.offline:
            try:
                self._preflight(system, user)
            except ContextOverflow:
                self.records.append({
                    "key": key, "provider": self.name, "model": self.model, "status": "raised",
                    "failure": "ContextOverflow", "cache_hit": False, "repaired": False, "attempts": 0,
                    "usage": asdict(Usage()), "wall_s": round(time.monotonic() - t0, 3),
                })
                raise
            raise OfflineMiss(f"{self.name}/{self.model}: no cached reply for key {key[:16]}")

        # 3. Send, validate, repair at most REPAIR_LIMIT times. A raised LLMError is recorded
        #    with the tokens already spent, then re-raised (D-032). LeakError is not an
        #    LLMError, so it passes through untouched (D-017, D-019).
        prompt = user
        attempts: list[dict[str, Any]] = []
        spent = Usage()
        repaired = False
        try:
            while True:
                self._preflight(system, prompt)
                raw = self._send_with_retry(system, prompt, schema_json)
                spent = spent + raw.usage
                attempt: dict[str, Any] = {
                    "text": raw.text,
                    "stop_reason": raw.stop_reason,
                    "model": raw.model,
                    "request_id": raw.request_id,
                    "usage": asdict(raw.usage),
                    "detail": raw.detail,
                    "error": None,
                }
                attempts.append(attempt)

                if raw.stop_reason == STOP_OVERFLOW:
                    raise ContextOverflow(f"{self.name}/{self.model}: context window exceeded {raw.detail}")
                if raw.stop_reason == STOP_REFUSAL:
                    status, data, failure = "failed", None, f"refusal:{raw.detail.get('category')}"
                    break
                if raw.stop_reason == STOP_MAX_TOKENS:
                    status, data, failure = "failed", None, STOP_MAX_TOKENS
                    break
                if raw.stop_reason != STOP_END:
                    status, data, failure = "failed", None, f"stop:{raw.stop_reason}"
                    break

                try:
                    data = schema.model_validate_json(raw.text).model_dump(mode="json")
                    status, failure = "ok", None
                    break
                except ValidationError as e:
                    attempt["error"] = _validation_summary(e)
                    if len(attempts) > REPAIR_LIMIT:
                        status, data, failure = "failed", None, "schema"
                        break
                    repaired = True
                    prompt = REPAIR_TEMPLATE.format(user=user, errors=attempt["error"])
                    self._gate(system, prompt, binary_sha256)
        except LLMError as e:
            self.records.append({
                "key": key,
                "provider": self.name,
                "model": self.model,
                "status": "raised",
                "failure": type(e).__name__,
                "cache_hit": False,
                "repaired": repaired,
                "attempts": len(attempts),
                "usage": asdict(spent),
                "wall_s": round(time.monotonic() - t0, 3),
            })
            raise

        comp = Completion(
            key=key,
            provider=self.name,
            model=self.model,
            status=status,
            failure=failure,
            data=data,
            raw_text=attempts[-1]["text"],
            attempts=tuple(attempts),
            usage=spent,
            cache_hit=False,
            repaired=repaired,
        )
        if self.cache is not None:
            self.cache.put(key, comp.to_entry(self.identity()))
        self.records.append(comp.record(time.monotonic() - t0))
        return comp

    # ---- internals ------------------------------------------------------------------

    @staticmethod
    def _gate(system: str, user: str, binary_sha256: str | None) -> None:
        assert_clean(system + "\n" + user, binary_sha256)

    def _backoff(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(self.backoff_cap_s, max(0.0, retry_after))
        base = min(self.backoff_cap_s, self.backoff_base_s * (2 ** attempt))
        return base * (0.5 + 0.5 * self._rng.random())

    def _send_with_retry(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        for attempt in range(self.max_retries + 1):
            try:
                return self._send(system, user, schema)
            except TransientError as e:
                if attempt == self.max_retries:
                    raise RetryExhausted(
                        f"{self.name}/{self.model}: gave up after {attempt + 1} attempts: {e}"
                    ) from e
                self.transient_retries += 1
                self._sleep(self._backoff(attempt, e.retry_after))
        raise AssertionError("unreachable")