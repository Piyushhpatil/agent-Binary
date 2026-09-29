"""D-021 table: factored verdict -> CWE id. Eval side only (D-008, D-021).

The analysis side never names a CWE (the leak gate rejects one, D-017), so the model answers
with four factored enums and this module turns them into a class id afterwards.
tests/test_isolation.py forbids analysis/ and llm/ from importing taintwalk.eval, so this
table cannot flow back into a prompt.

derive_cwe() returns:
- None       mechanism "none": no flaw claimed, nothing to map;
- "CWE-NNN"  the one class the combination names;
- AMBIGUOUS  a flaw is claimed but the combination names no single class. D-008 counts it at
             detection and mechanism level, never at exact level.
Unknown enum values raise: the schema makes them impossible, so one here is an upstream bug.
"""
from __future__ import annotations

AMBIGUOUS = "ambiguous"

MECHANISMS = frozenset({
    "none", "out_of_bounds_access", "integer_overflow", "integer_underflow",
    "overflowed_size_to_buffer", "divide_by_zero", "untrusted_format_string",
    "os_command_injection", "untrusted_loop_bound", "untrusted_allocation_size", "other",
})
REGIONS = frozenset({"stack", "heap", "global", "unknown", "not_applicable"})
ACCESSES = frozenset({"read", "write", "not_applicable"})
DIRECTIONS = frozenset({"past_end", "before_start", "not_applicable"})

CORPUS_CWES = ("CWE-78", "CWE-121", "CWE-122", "CWE-124", "CWE-126", "CWE-127", "CWE-134",
               "CWE-190", "CWE-191", "CWE-369", "CWE-606", "CWE-680", "CWE-789")

# Mechanisms that name one class whatever region, access and direction say.
BY_MECHANISM = {
    "integer_overflow": "CWE-190",
    "integer_underflow": "CWE-191",
    "overflowed_size_to_buffer": "CWE-680",
    "divide_by_zero": "CWE-369",
    "untrusted_format_string": "CWE-134",
    "os_command_injection": "CWE-78",
    "untrusted_loop_bound": "CWE-606",
    "untrusted_allocation_size": "CWE-789",
}

# out_of_bounds_access: (access, direction, region) -> class. Region None means any region.
OUT_OF_BOUNDS = {
    ("write", "past_end", "stack"): "CWE-121",
    ("write", "past_end", "heap"): "CWE-122",
    ("write", "before_start", None): "CWE-124",
    ("read", "past_end", None): "CWE-126",
    ("read", "before_start", None): "CWE-127",
}

_OOB_CWES = frozenset(OUT_OF_BOUNDS.values())


def _check(value: str, allowed: frozenset[str], field: str) -> None:
    if value not in allowed:
        raise ValueError(f"unknown {field} {value!r}; allowed: {sorted(allowed)}")


def derive_cwe(mechanism: str, region: str, access: str, direction: str) -> str | None:
    """Map one factored verdict to a class id, None, or AMBIGUOUS (see module docstring)."""
    _check(mechanism, MECHANISMS, "mechanism")
    _check(region, REGIONS, "region")
    _check(access, ACCESSES, "access")
    _check(direction, DIRECTIONS, "direction")
    if mechanism == "none":
        return None
    if mechanism in BY_MECHANISM:
        return BY_MECHANISM[mechanism]
    if mechanism == "out_of_bounds_access":
        return (OUT_OF_BOUNDS.get((access, direction, region))
                or OUT_OF_BOUNDS.get((access, direction, None))
                or AMBIGUOUS)
    return AMBIGUOUS  # "other"


def cwe_of_verdict(verdict: dict) -> str | None:
    """derive_cwe() on a verdict dict as stored in summaries.json."""
    return derive_cwe(verdict["mechanism"], verdict["region"], verdict["access"], verdict["direction"])


def expected_mechanism(cwe: str) -> str:
    """The mechanism D-021 maps a case's class to (the D-008 mechanism level)."""
    if cwe in _OOB_CWES:
        return "out_of_bounds_access"
    for mechanism, c in BY_MECHANISM.items():
        if c == cwe:
            return mechanism
    raise ValueError(f"{cwe!r} is not a class the D-021 table maps to")