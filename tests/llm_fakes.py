"""Test doubles for the llm package.

Deliberately not named test_*.py: test modules import it, pytest never collects it.
"""
from __future__ import annotations

import random
from typing import Any

from pydantic import BaseModel, Field

from taintwalk.llm.base import STOP_END, LLMProvider, RawResponse, Usage

GOOD_TEXT = '{"ok": true, "echo": "taintwalk", "count": 3}'


class Ping(BaseModel):
    ok: bool
    echo: str
    count: int = Field(ge=0, le=10)


def ok_response(text: str = GOOD_TEXT, stop_reason: str = STOP_END,
                input_tokens: int = 40, output_tokens: int = 20, **detail: Any) -> RawResponse:
    return RawResponse(
        text=text,
        stop_reason=stop_reason,
        usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens),
        model="fake-1",
        request_id=None,
        detail=dict(detail),
    )


class FakeProvider(LLMProvider):
    """Replays a scripted list of RawResponse objects or exceptions, one per _send() call."""

    name = "fake"

    def __init__(self, responses: list[Any], *, params: dict[str, Any] | None = None, **kw: Any) -> None:
        self.sleeps: list[float] = []
        kw.setdefault("sleep", self.sleeps.append)
        kw.setdefault("rng", random.Random(0))
        super().__init__("fake-1", params if params is not None else {"p": 1}, **kw)
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def _send(self, system: str, user: str, schema: dict[str, Any]) -> RawResponse:
        self.calls.append({"system": system, "user": user, "schema": schema})
        if not self.responses:
            raise AssertionError("FakeProvider ran out of scripted responses")
        r = self.responses.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r
