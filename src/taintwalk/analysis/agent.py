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
import threading
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

# v2 (mini-step 10e, dev run): the v1 step prompt let the model read addresses off Ghidra names
# (FUN_00101c04), which carry the image base; tools use program.json addresses (0x1c04, D-016), so
# every v1 target was refused. v2 lists each target explicitly and names the valid ones on a refusal.
AGENT_PROMPT_VERSION = 2
MAX_LISTED_TARGETS = 20
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
- target is copied exactly from a "target 0x..." entry in the lists you are shown. Function names such as FUN_00101c04 contain a different number; never use that number as a target.
- If no listed target could change the judgement, choose finish.
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
    key: str = ""             # the call's cache key: the same live and on replay, so safe to record


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


def _target_line(it: dict[str, str]) -> str:
    return f"  target {it['addr']} = {it['name']} ({it['status']})\n"


def valid_targets(state: AgentState) -> list[str]:
    """Targets the model has been shown and may use: the root's direct callees plus every listing so
    far, minus out-of-scope stubs (not in the closure) and the root itself, in address order."""
    seen: set[str] = set()
    for it in list_callees(state.scope, state.root):
        if it["status"] != "out_of_scope":
            seen.add(it["addr"])
    for items in state.listings.values():
        for it in items:
            if it["status"] != "out_of_scope":
                seen.add(it["addr"])
    seen.discard(state.root)
    return sorted(seen, key=lambda a: int(a, 16))


def refusal_detail(state: AgentState, err: Exception) -> str:
    valid = valid_targets(state)
    shown = ", ".join(valid[:MAX_LISTED_TARGETS]) or "none"
    more = f" (and {len(valid) - MAX_LISTED_TARGETS} more)" if len(valid) > MAX_LISTED_TARGETS else ""
    return f"{err}. Valid targets: {shown}{more}"


def render_step_user(state: AgentState) -> str:
    """The step prompt: the root's numbered code, its direct callees as explicit targets, then
    everything gathered so far."""
    parts = [render_user(state.root_name, state.lines),
             "\nFunctions called by the function under analysis "
             "(use the target exactly as written):\n"]
    direct = list_callees(state.scope, state.root)
    if not direct:
        parts.append("  (none)\n")
    parts += [_target_line(it) for it in direct]
    parts.append("\nEvidence gathered so far:\n")
    if not state.steps:
        parts.append("  (nothing yet)\n")
    for s in state.steps:
        detail = f" {s.detail}" if s.detail else ""
        parts.append(f"  step {s.index}: {s.action} {s.target} -> {s.outcome}{detail}\n")
    for addr, items in state.listings.items():
        parts.append(f"\nFunctions called by {addr}:\n")
        if not items:
            parts.append("  (none)\n")
        parts += [_target_line(it) for it in items]
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
            return Decision(None, metered, 1, failure=c.failure or "unknown", key=c.key or "")
        return Decision(AgentAction.model_validate(c.data), metered, 1, key=c.key or "")


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
    call_keys: list[str] = []     # every model call for this root, in order (cost from the cache)

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
        if d.key:
            call_keys.append(d.key)
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
                    if row.get("cache_key"):
                        call_keys.append(row["cache_key"])
                    step_calls += 1
                    m = meter_prompt_file(run_dir / "prompts" / f"{stem(sha, act.target)}.json",
                                          ratio=caps.token_chars_ratio)
                    metered += m
                    step_metered += m
                detail = view.status
        except ToolError as e:
            invalid += 1
            state.steps.append(Step(idx, act.action, act.target, act.reason, "refused",
                                    refusal_detail(state, e), step_metered, step_calls))
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
        if row.get("cache_key"):
            call_keys.append(row["cache_key"])
        agent_fields["judge"] = row.get("status") or "unknown"

    agent_fields["call_keys"] = list(call_keys)
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
        "call_keys": agent_fields["call_keys"],
        "metered_tokens": agent_fields["metered_tokens"],
        "evidence_chars": len(evidence),
        "judge": agent_fields.get("judge", ""),
        **omissions,
    }
    (agent_dir / f"{stem(sha, addr)}{tag}.json").write_text(
        json.dumps(transcript, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return row


# ---------------------------------------------------------------------------
# Program driver (mini-step 8): the agent at every root of one program, written
# into a run dir shaped like the walk's so one scorer can read both.
# ---------------------------------------------------------------------------

POLICIES = ("llm", "scripted")


def make_policy(name: str, provider: LLMProvider) -> Any:
    """One of the two policies by name. ScriptedPolicy makes no model call of its own."""
    if name == "scripted":
        return ScriptedPolicy()
    if name == "llm":
        return LLMPolicy(provider=provider)
    raise ValueError(f"unknown agent policy {name!r}; expected one of {POLICIES}")


def _fn_name(prog: dict[str, Any], addr: str) -> str:
    for f in prog["functions"]:
        if f["addr"] == addr:
            return f.get("ghidra_name") or addr
    return addr


def walk_agent_program(provider: LLMProvider, prog: dict[str, Any], run_dir: Path,
                       roots: Iterable[str], *, policy_name: str = "llm",
                       caps: Caps | None = None, retry_failed: bool = False) -> dict[str, Any]:
    """Run the agent at each root, then write summaries.json and agent.json under run_dir.

    summaries.json carries the walk's shape, {addr: record or null}, so a root that abstained is a
    null entry exactly as in a fixed walk and D-008 scores it as an abstention, never as "not
    vulnerable". Roots run in numeric address order, which carries no label (D-036)."""
    from taintwalk.analysis.callgraph import addr_key

    run_dir = Path(run_dir)
    caps = caps or Caps.from_config()
    if policy_name not in POLICIES:
        raise ValueError(f"unknown agent policy {policy_name!r}; expected one of {POLICIES}")
    sha = prog["binary"]["sha256"]
    order = sorted(set(roots), key=addr_key)
    if not order:
        raise ValueError("agent mode needs at least one root address")
    in_scope = {f["addr"] for f in prog["functions"] if f.get("in_scope")}
    missing = [a for a in order if a not in in_scope]
    if missing:
        raise ValueError(f"roots not in scope in this program: {missing}")

    summaries: dict[str, Any] = {}
    functions: dict[str, Any] = {}
    overflows = 0
    for addr in order:
        try:
            row = run_agent(provider, prog, addr, run_dir,
                            policy=make_policy(policy_name, provider),
                            caps=caps, retry_failed=retry_failed)
        except ContextOverflow as e:
            overflows += 1
            row = _abstention_row(prog, addr, _fn_name(prog, addr), "context_overflow",
                                  {"agent": {"policy": policy_name, "stop": "preflight_overflow",
                                             "steps": 0, "calls": 0, "metered_tokens": 0,
                                             "judge": "context_overflow", "detail": str(e)[:200]}})
        summaries[addr] = row.get("record")
        a = row.get("agent") or {}
        functions[addr] = {
            "function": row.get("function") or _fn_name(prog, addr),
            "status": row.get("status"), "failure": row.get("failure") or "",
            "policy": a.get("policy", policy_name), "stop": a.get("stop", ""),
            "steps": a.get("steps", 0), "calls": a.get("calls", 0),
            "metered_tokens": a.get("metered_tokens", 0),
            "invalid_actions": a.get("invalid_actions", 0),
            "repeated_actions": a.get("repeated_actions", 0),
            "summaries_fetched": a.get("summaries_fetched", []),
            "code_read": a.get("code_read", []),
            "evidence_chars": a.get("evidence_chars", 0),
            "judge": a.get("judge", ""),
            "call_keys": a.get("call_keys", []),
        }

    result = {
        "binary_sha256": sha,
        "mode": "agent",
        "policy": policy_name,
        "agent_prompt_version": AGENT_PROMPT_VERSION,
        "caps": {"max_actions": caps.max_actions, "max_calls": caps.max_calls,
                 "max_tokens_per_root": caps.max_tokens_per_root,
                 "read_code_max_chars": caps.read_code_max_chars,
                 "evidence_max_chars": caps.evidence_max_chars,
                 "token_chars_ratio": caps.token_chars_ratio},
        "roots": order,
        "functions": functions,
        "context_overflows": overflows,
        "calls": sum(f["calls"] for f in functions.values()),
        "metered_tokens": sum(f["metered_tokens"] for f in functions.values()),
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "summaries.json").write_text(
        json.dumps(summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_dir / "agent.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def usage_line(run_dir: Path) -> str | None:
    """walker.walk_report's `tokens (this run)` line, from the usage.json the llm layer wrote for
    this process. Live calls are the records that were not cache hits; None without the file."""
    f = Path(run_dir) / "usage.json"
    if not f.is_file():
        return None
    doc = json.loads(f.read_text(encoding="utf-8"))
    recs = [r for p in doc.get("providers", []) for r in p.get("records", [])]
    live = [r for r in recs if not r.get("cache_hit") and r.get("usage")]
    return (f"tokens (this run)  : in {sum(r['usage']['input_tokens'] for r in live)}  "
            f"out {sum(r['usage']['output_tokens'] for r in live)}  "
            f"model time {sum(r.get('wall_s') or 0 for r in live):.1f} s  "
            f"cache hits {sum(bool(r.get('cache_hit')) for r in recs)} of {len(recs)} calls")


def agent_report(result: dict[str, Any], run_dir: Path | None = None) -> int:
    """One summary line. 0 only if every root has an entry and nothing overflowed, which is
    walk_report's rule (D-026 amendment), so both modes report success the same way. With
    run_dir, also the tokens line walk_all parses (TOKENS_LINE), as the fixed walk prints."""
    fns = result["functions"]
    answered = sum(1 for f in fns.values() if f["judge"] == "ok")
    stops: dict[str, int] = {}
    for f in fns.values():
        stops[f["stop"] or "none"] = stops.get(f["stop"] or "none", 0) + 1
    print(f"roots {len(fns)}  answered {answered}  policy {result['policy']}  "
          f"calls {result['calls']}  metered {result['metered_tokens']}  "
          f"overflows {result['context_overflows']}")
    print("stops: " + ", ".join(f"{k} {v}" for k, v in sorted(stops.items())))
    line = usage_line(run_dir) if run_dir is not None else None
    if line:
        print(line)
    ok = result["context_overflows"] == 0 and len(fns) == len(result["roots"])
    print("AGENT OK" if ok else "AGENT FAIL")
    return 0 if ok else 1


class RunBudget:
    """A metered-token ceiling for one `walk --all` run (D-042).

    Claimed before a program starts and charged after it finishes, so the overshoot is bounded by
    jobs x the per-program cap -- the bound D-042 pre-registers. Which programs get skipped depends
    on thread scheduling, and that is harmless: a run that hits the ceiling is incomplete by
    construction (the skipped programs have no summaries), exits non-zero, and the scorer fails
    closed on a missing root. A ceilinged run is void, never a different result.
    """

    def __init__(self, ceiling: int) -> None:
        if ceiling < 1:
            raise ValueError("a run ceiling must be positive; 0 means unset")
        self.ceiling = int(ceiling)
        self.spent = 0
        self.skipped: list[str] = []
        self._lock = threading.Lock()

    def claim(self, name: str) -> bool:
        """True if this program may start. Records the name when it may not."""
        with self._lock:
            if self.spent >= self.ceiling:
                self.skipped.append(name)
                return False
            return True

    def charge(self, amount: int) -> int:
        with self._lock:
            self.spent += max(0, int(amount))
            return self.spent

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"ceiling": self.ceiling, "spent": self.spent, "skipped": sorted(self.skipped)}


def program_metered(run_dir: Path) -> int:
    """What one agent program spent, read from the agent.json it wrote. 0 when there is none, so a
    fixed walk (which writes walk.json instead) is never charged."""
    f = Path(run_dir) / "agent.json"
    if not f.is_file():
        return 0
    try:
        return int(json.loads(f.read_text(encoding="utf-8")).get("metered_tokens") or 0)
    except (ValueError, OSError, TypeError):
        return 0