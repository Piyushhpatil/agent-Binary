"""Phase 10 agentic mode (D-042): the agent gathers evidence, the frozen judge gives the verdict.

Two policies share one loop. ScriptedPolicy (rung A1) reads the no-context summary of every readable
direct callee, in address order, then stops: no model call chooses anything. LLMPolicy (rung A2) asks
the model for one AgentAction per step, so the model owns the control flow.

Both end the same way: the evidence gathered is handed to the *unchanged* prompt-v2 judge as
build_prompt(root, callee_context=<evidence>), through analyze_function. The evidence block is the
only input that differs between R4, A1, A2 and R5, so any difference in verdicts is attributable to
it. An agent that gathers nothing produces an empty evidence block, so its judge prompt is R4's byte
for byte -- the floor the scorer asserts.

Evidence has two parts. Part A is the D-026 callee-summary block, rendered by the unchanged
render_callee_context (its ordering, its budget rule, its 120-char cap on model text). Part B is the
code the agent chose to read, under its own header, unnumbered so evidence_line cannot shift. Over
the budget, whole code reads are dropped from the end first; only then does Part A's own rule drop
summaries.

Metering reads the transcript, not the wallet: tokens = ceil(chars / token_chars_ratio) over every
prompt and reply, cache hits included, so an offline replay gets exactly the live run's budget and
takes the same trajectory. Real token counts are recorded separately by the llm layer.

LeakError is never caught here.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

from pydantic import BaseModel, Field, model_validator

from taintwalk.analysis.agent_tools import (
    Scope, ToolError, list_callees, make_scope, read_code, read_summary,
)
from taintwalk.analysis.analyze_one import analyze_function, stem
from taintwalk.analysis.prompts import (
    SYSTEM, CalleeView, prepare_code, render_callee_context, render_user,
)
from taintwalk.llm.base import ContextOverflow, LLMProvider

AGENT_PROMPT_VERSION = 1
ADDR_RE = re.compile(r"0x[0-9a-f]+")

STOP_REASONS = ("finish", "max_actions", "max_calls", "max_tokens",
                "preflight_overflow", "step_failed")

CODE_HEADER = (
    "Code of functions this analysis asked to read. It is shown without line numbers; "
    "evidence_line refers only to the numbered code above.\n"
)

AGENT_SYSTEM = """You are gathering evidence about one function from a stripped binary, so that a separate step can judge whether it is memory-unsafe.

You never give a verdict. Your only job is to choose what to read next.

Actions:
- list_callees: list the internal functions called by a function already in view. target is its address.
- read_code: read the decompiled code of a called function. target is its address.
- read_summary: read an independent analysis of a called function, written without any knowledge of this caller. target is its address.
- finish: stop gathering. target must be the empty string.

Rules:
- target is a lowercase hex address such as 0x1234, taken from the code or from an earlier result.
- You may not target the function under analysis. Its code is already shown to you.
- Repeating an action you have already performed is wasted; it costs a step and returns nothing new.
- Choose finish as soon as further reading could not change the judgement.
- reason is one short sentence saying why this action helps.

Reply with one JSON object holding reason, action and target.
"""


class AgentAction(BaseModel):
    """One step the policy commits to. No optional and no nullable fields (D-021): absence is "".

    The cross-field rule is validated client-side, so a violation is repaired once by the llm
    pipeline exactly like D-021's vulnerable/mechanism rule, instead of silently passing through.
    """

    model_config = {"extra": "forbid"}

    reason: str = Field(description="One short sentence: why this action helps.")
    action: Literal["list_callees", "read_code", "read_summary", "finish"]
    target: str = Field(description="A lowercase hex address like 0x1234, or empty for finish.")

    @model_validator(mode="after")
    def _target_matches_action(self) -> "AgentAction":
        if self.action == "finish":
            if self.target != "":
                raise ValueError("target must be empty when action is finish")
        elif not ADDR_RE.fullmatch(self.target):
            raise ValueError("target must be a lowercase hex address like 0x1234")
        return self


@dataclass(frozen=True)
class Caps:
    max_actions: int
    max_calls: int
    max_tokens_per_root: int
    read_code_max_chars: int
    evidence_max_chars: int
    token_chars_ratio: float

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None = None) -> "Caps":
        if cfg is None:
            from taintwalk.config import load_config
            cfg = load_config()
        a = cfg["agent"]
        return cls(
            max_actions=int(a["max_actions"]),
            max_calls=int(a["max_calls"]),
            max_tokens_per_root=int(a["max_tokens_per_root"]),
            read_code_max_chars=int(a["read_code_max_chars"]),
            evidence_max_chars=int(a["evidence_max_chars"]),
            token_chars_ratio=float(a["token_chars_ratio"]),
        )


@dataclass
class Step:
    index: int
    action: str
    target: str
    reason: str
    outcome: str          # ok | refused | repeated | failed
    detail: str
    metered: int
    calls: int

    def as_dict(self) -> dict[str, Any]:
        return {"index": self.index, "action": self.action, "target": self.target,
                "reason": self.reason, "outcome": self.outcome, "detail": self.detail,
                "metered_tokens": self.metered, "calls": self.calls}


@dataclass
class AgentState:
    scope: Scope
    sha: str
    root: str
    root_name: str
    lines: tuple[str, ...]
    caps: Caps
    steps: list[Step] = field(default_factory=list)
    listings: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    code_reads: dict[str, str] = field(default_factory=dict)
    fetched: dict[str, CalleeView] = field(default_factory=dict)


@dataclass
class Decision:
    """What one policy step produced, plus what it cost."""
    action: AgentAction | None
    metered: int = 0
    calls: int = 0
    failure: str = ""
    overflow: bool = False


def _attempt_text(a: Any) -> str:
    """An attempt is a dict in the persisted prompt file and an object on a live Completion."""
    if isinstance(a, dict):
        return a.get("text") or ""
    return getattr(a, "text", "") or ""


def meter(system: str, user: str, replies: Iterable[str], *, ratio: float) -> int:
    """Metered tokens for one exchange: ceil(chars / ratio) over the prompt and every reply."""
    chars = len(system) + 1 + len(user) + sum(len(r) for r in replies)
    return math.ceil(chars / ratio)


def meter_prompt_file(path: Path, *, ratio: float) -> int:
    """Meter an analyze_function call exactly, after the fact, from the prompt file it wrote."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return meter(SYSTEM, doc["user"], [_attempt_text(a) for a in doc.get("attempts", [])], ratio=ratio)


def render_code_reads(items: list[tuple[str, str, str]]) -> str:
    """Part B of the evidence: code the agent asked for, unnumbered, in fetch order."""
    if not items:
        return ""
    out = [CODE_HEADER]
    for addr, name, text in items:
        out.append(f"\n{name} at {addr}:\n{text}\n")
    return "".join(out)


def build_evidence(lines: tuple[str, ...], views: list[CalleeView],
                   code_items: list[tuple[str, str, str]], *, max_chars: int) -> tuple[str, dict[str, int]]:
    """Assemble Part A + Part B inside max_chars, dropping whole code reads from the end first.

    Part A keeps D-026's own ordering and drop rule; it is never rewritten here. With nothing
    gathered the result is "", which makes the judge prompt byte-identical to R4's."""
    for n in range(len(code_items), -1, -1):
        part_b = render_code_reads(code_items[:n])
        budget = max_chars - len(part_b)
        if budget < 1:
            continue
        if views:
            try:
                ctx = render_callee_context(lines, views, max_chars=budget)
            except ValueError:
                continue
            text = ctx.text if not part_b else ctx.text.rstrip("\n") + "\n" + part_b
            omitted_summaries = len(ctx.omitted)      # CalleeContext.omitted is a tuple of addrs
        else:
            text = part_b
            omitted_summaries = 0
        if len(text) <= max_chars:
            return text, {"omitted_code_reads": len(code_items) - n,
                          "omitted_summaries": omitted_summaries}
    return "", {"omitted_code_reads": len(code_items), "omitted_summaries": len(views)}


def render_step_user(state: AgentState) -> str:
    """The step prompt: the root's numbered code, then everything gathered so far."""
    parts = [render_user(state.root_name, state.lines), "\nEvidence gathered so far:\n"]
    if not state.steps:
        parts.append("  (nothing yet)\n")
    for s in state.steps:
        detail = f" {s.detail}" if s.detail else ""
        parts.append(f"  step {s.index}: {s.action} {s.target} -> {s.outcome}{detail}\n")
    for addr, items in state.listings.items():
        parts.append(f"\nFunctions called by {addr}:\n")
        if not items:
            parts.append("  (none)\n")
        for it in items:
            parts.append(f"  {it['addr']} {it['name']} ({it['status']})\n")
    for addr, text in state.code_reads.items():
        parts.append(f"\nCode of {addr}:\n{text}\n")
    if state.fetched:
        ctx = render_callee_context(state.lines, list(state.fetched.values()),
                                    max_chars=state.caps.evidence_max_chars)
        parts.append("\n" + ctx.text)
    parts.append(f"\nSteps used: {len(state.steps)} of {state.caps.max_actions}. "
                 f"Choose the next action.\n")
    return "".join(parts)


class ScriptedPolicy:
    """Rung A1: read every readable direct callee's no-context summary, address order, then finish.

    No model call decides anything here, which is what separates "agency helped" from "different
    context helped" when A2 is compared against it."""

    name = "scripted"

    def choose(self, state: AgentState) -> Decision:
        done = {s.target for s in state.steps if s.action == "read_summary"}
        for c in list_callees(state.scope, state.root):
            if c["status"] == "readable" and c["addr"] not in done:
                return Decision(AgentAction(reason="read the next direct callee's summary",
                                            action="read_summary", target=c["addr"]))
        return Decision(AgentAction(reason="every direct callee has been read",
                                    action="finish", target=""))


@dataclass
class LLMPolicy:
    """Rung A2: the model chooses each action, so the model owns the control flow."""

    provider: LLMProvider
    name: str = "llm"

    def choose(self, state: AgentState) -> Decision:
        user = render_step_user(state)
        ratio = state.caps.token_chars_ratio
        try:
            c = self.provider.complete(AGENT_SYSTEM, user, AgentAction, binary_sha256=state.sha)
        except ContextOverflow:
            return Decision(None, meter(AGENT_SYSTEM, user, (), ratio=ratio), 1, overflow=True)
        metered = meter(AGENT_SYSTEM, user,
                        [_attempt_text(a) for a in (getattr(c, "attempts", None) or [])], ratio=ratio)
        if not c.ok:
            return Decision(None, metered, 1, failure=c.failure or "unknown")
        return Decision(AgentAction.model_validate(c.data), metered, 1)


def _abstention_row(prog: dict[str, Any], addr: str, name: str, failure: str,
                    extra: dict[str, Any]) -> dict[str, Any]:
    """A deliberately minimal row for a root whose judge never ran. record is None, so every
    downstream rule treats it as an abstention (D-008), never as "not vulnerable"."""
    row = {"binary_sha256": prog["binary"]["sha256"], "address": addr, "function": name,
           "record": None, "status": "failed", "failure": failure,
           "prompt_version": None, "cache_hit": False, "usage": None}
    row.update(extra)
    return row


def run_agent(provider: LLMProvider, prog: dict[str, Any], addr: str, run_dir: Path, *,
              policy: Any, caps: Caps, tag: str = ".judge", extra: dict[str, Any] | None = None,
              retry_failed: bool = False) -> dict[str, Any]:
    """Gather evidence for one root under the caps, then run the frozen judge on it.

    Returns analyze_function's row for the judge call, carrying the agent fields under "agent", or a
    minimal abstention row when the budget could not cover the judge."""
    run_dir = Path(run_dir)
    scope = make_scope(prog, addr)
    sha = prog["binary"]["sha256"]
    root_fn = scope.fns[addr]
    name = root_fn.get("ghidra_name") or addr
    lines, _, _ = prepare_code(root_fn["pseudo_c"])

    state = AgentState(scope=scope, sha=sha, root=addr, root_name=name, lines=lines, caps=caps)
    code_items: list[tuple[str, str, str]] = []
    executed: set[tuple[str, str]] = set()
    calls = 0
    metered = 0
    invalid = 0
    repeated = 0
    stop = ""

    while True:
        if len(state.steps) >= caps.max_actions:
            stop = "max_actions"
            break
        if calls + 1 >= caps.max_calls:          # one call is reserved for the judge
            stop = "max_calls"
            break
        if metered >= caps.max_tokens_per_root:
            stop = "max_tokens"
            break

        d = policy.choose(state)
        calls += d.calls
        metered += d.metered
        idx = len(state.steps) + 1

        if d.overflow:
            state.steps.append(Step(idx, "", "", "", "failed", "step prompt over the preflight budget",
                                    d.metered, d.calls))
            stop = "preflight_overflow"
            break
        if d.action is None:
            state.steps.append(Step(idx, "", "", "", "failed", d.failure, d.metered, d.calls))
            stop = "step_failed"
            break

        act = d.action
        if act.action == "finish":
            state.steps.append(Step(idx, "finish", "", act.reason, "ok", "", d.metered, d.calls))
            stop = "finish"
            break

        key = (act.action, act.target)
        if key in executed:
            repeated += 1
            state.steps.append(Step(idx, act.action, act.target, act.reason, "repeated",
                                    "already performed", d.metered, d.calls))
            continue

        step_calls = d.calls
        step_metered = d.metered
        try:
            if act.action == "list_callees":
                items = list_callees(scope, act.target)
                state.listings[act.target] = items
                detail = f"{len(items)} callees"
            elif act.action == "read_code":
                text = read_code(scope, act.target, max_chars=caps.read_code_max_chars)
                state.code_reads[act.target] = text
                code_items.append((act.target, scope.fns[act.target].get("ghidra_name") or act.target, text))
                detail = f"{len(text)} chars"
            else:
                view, row = read_summary(provider, scope, act.target, run_dir, retry_failed=retry_failed)
                state.fetched[act.target] = view
                if row is not None:
                    calls += 1
                    step_calls += 1
                    m = meter_prompt_file(run_dir / "prompts" / f"{stem(sha, act.target)}.json",
                                          ratio=caps.token_chars_ratio)
                    metered += m
                    step_metered += m
                detail = view.status
        except ToolError as e:
            invalid += 1
            state.steps.append(Step(idx, act.action, act.target, act.reason, "refused", str(e),
                                    step_metered, step_calls))
            continue

        executed.add(key)
        state.steps.append(Step(idx, act.action, act.target, act.reason, "ok", detail,
                                step_metered, step_calls))

    evidence, omissions = build_evidence(lines, list(state.fetched.values()), code_items,
                                         max_chars=caps.evidence_max_chars)

    agent_fields = {
        "policy": policy.name,
        "agent_prompt_version": AGENT_PROMPT_VERSION,
        "steps": len(state.steps),
        "calls": calls,
        "metered_tokens": metered,
        "stop": stop,
        "invalid_actions": invalid,
        "repeated_actions": repeated,
        "summaries_fetched": sorted(state.fetched),
        "code_read": [a for a, _, _ in code_items],
        "listed": sorted(state.listings),
        "evidence_chars": len(evidence),
        "caps": {"max_actions": caps.max_actions, "max_calls": caps.max_calls,
                 "max_tokens_per_root": caps.max_tokens_per_root},
        **omissions,
    }

    no_calls_left = calls + 1 > caps.max_calls
    no_tokens_left = metered >= caps.max_tokens_per_root
    if no_calls_left or no_tokens_left:
        agent_fields["stop"] = stop or ("max_calls" if no_calls_left else "max_tokens")
        agent_fields["judge"] = "agent:budget"
        row = _abstention_row(prog, addr, name, "agent:budget", {"agent": agent_fields})
    else:
        row = analyze_function(provider, prog, addr, run_dir, retry_failed=retry_failed,
                               callee_context=evidence, tag=tag,
                               extra={"agent": agent_fields})
        calls += 1
        metered += meter_prompt_file(run_dir / "prompts" / f"{stem(sha, addr)}{tag}.json",
                                     ratio=caps.token_chars_ratio)
        agent_fields["calls"] = calls
        agent_fields["metered_tokens"] = metered
        agent_fields["judge"] = row.get("status") or "unknown"

    if extra:
        row.update(extra)

    agent_dir = run_dir / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)
    transcript = {
        "address": addr,
        "function": name,
        "binary_sha256": sha,
        "policy": policy.name,
        "agent_prompt_version": AGENT_PROMPT_VERSION,
        "stop": agent_fields["stop"],
        "steps": [s.as_dict() for s in state.steps],
        "calls": agent_fields["calls"],
        "metered_tokens": agent_fields["metered_tokens"],
        "evidence_chars": len(evidence),
        "judge": agent_fields.get("judge", ""),
        **omissions,
    }
    (agent_dir / f"{stem(sha, addr)}{tag}.json").write_text(
        json.dumps(transcript, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return row