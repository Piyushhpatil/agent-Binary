"""Phase 10 (D-042): the agent block exists, is typed, and the evidence cap equals the walk's callee cap."""
from taintwalk.config import load_config

INT_KEYS = ("max_actions", "max_calls", "max_tokens_per_root", "max_tokens_per_run",
            "read_code_max_chars", "evidence_max_chars")


def test_agent_block_present_and_typed():
    cfg = load_config()
    a = cfg["agent"]
    assert set(a) == set(INT_KEYS) | {"token_chars_ratio"}
    for k in INT_KEYS:
        assert type(a[k]) is int and a[k] >= 0, k
    assert a["max_actions"] >= 1 and a["max_calls"] > a["max_actions"]
    assert type(a["token_chars_ratio"]) is float and a["token_chars_ratio"] > 0
    # The judge prompt is build_prompt(root, callee_context=evidence): the D-026 budget test already proves
    # system + user + walk cap fits the preflight budget, so the evidence cap must not exceed it.
    assert a["evidence_max_chars"] == cfg["walk"]["callee_context_max_chars"]
