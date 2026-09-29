"""D-021 table (eval side). Checked against the Verdict schema it maps from, so a schema change
that adds an enum value fails here instead of silently mapping to nothing."""
from __future__ import annotations

import itertools

import pytest

from taintwalk.analysis.summary_schema import Verdict
from taintwalk.corpus.select import corpus_cfg
from taintwalk.eval.cwe_map import (
    ACCESSES,
    AMBIGUOUS,
    CORPUS_CWES,
    DIRECTIONS,
    MECHANISMS,
    REGIONS,
    cwe_of_verdict,
    derive_cwe,
    expected_mechanism,
)

FIELDS = ("mechanism", "region", "access", "direction")

D021_ROWS = [
    (("out_of_bounds_access", "stack", "write", "past_end"), "CWE-121"),
    (("out_of_bounds_access", "heap", "write", "past_end"), "CWE-122"),
    (("out_of_bounds_access", "stack", "write", "before_start"), "CWE-124"),
    (("out_of_bounds_access", "heap", "read", "past_end"), "CWE-126"),
    (("out_of_bounds_access", "global", "read", "before_start"), "CWE-127"),
    (("integer_overflow", "not_applicable", "not_applicable", "not_applicable"), "CWE-190"),
    (("integer_underflow", "not_applicable", "not_applicable", "not_applicable"), "CWE-191"),
    (("overflowed_size_to_buffer", "heap", "write", "past_end"), "CWE-680"),
    (("divide_by_zero", "not_applicable", "not_applicable", "not_applicable"), "CWE-369"),
    (("untrusted_format_string", "not_applicable", "not_applicable", "not_applicable"), "CWE-134"),
    (("os_command_injection", "not_applicable", "not_applicable", "not_applicable"), "CWE-78"),
    (("untrusted_loop_bound", "stack", "write", "past_end"), "CWE-606"),
    (("untrusted_allocation_size", "heap", "not_applicable", "not_applicable"), "CWE-789"),
]


def _schema_enum(field: str) -> set[str]:
    schema = Verdict.model_json_schema()
    prop = schema["properties"][field]
    if "$ref" in prop:
        prop = schema["$defs"][prop["$ref"].rsplit("/", 1)[-1]]
    assert "enum" in prop, f"{field}: no enum in the Verdict schema: {prop}"
    return set(prop["enum"])


def test_enum_sets_match_the_verdict_schema():
    assert _schema_enum("mechanism") == set(MECHANISMS)
    assert _schema_enum("region") == set(REGIONS)
    assert _schema_enum("access") == set(ACCESSES)
    assert _schema_enum("direction") == set(DIRECTIONS)


@pytest.mark.parametrize("fields, cwe", D021_ROWS, ids=[c for _, c in D021_ROWS])
def test_d021_rows(fields, cwe):
    assert derive_cwe(*fields) == cwe
    assert cwe_of_verdict(dict(zip(FIELDS, fields))) == cwe


def test_region_matters_only_for_past_end_writes():
    for region in REGIONS:
        assert derive_cwe("out_of_bounds_access", region, "write", "before_start") == "CWE-124"
        assert derive_cwe("out_of_bounds_access", region, "read", "past_end") == "CWE-126"
        assert derive_cwe("out_of_bounds_access", region, "read", "before_start") == "CWE-127"
    for region in ("global", "unknown", "not_applicable"):
        assert derive_cwe("out_of_bounds_access", region, "write", "past_end") == AMBIGUOUS


def test_ambiguous_combinations():
    for fields in [
        ("out_of_bounds_access", "stack", "not_applicable", "past_end"),
        ("out_of_bounds_access", "stack", "write", "not_applicable"),
        ("out_of_bounds_access", "not_applicable", "not_applicable", "not_applicable"),
        ("other", "stack", "write", "past_end"),
        ("other", "not_applicable", "not_applicable", "not_applicable"),
    ]:
        assert derive_cwe(*fields) == AMBIGUOUS, fields


def test_none_names_no_class_whatever_the_fields_say():
    for r, a, d in itertools.product(sorted(REGIONS), sorted(ACCESSES), sorted(DIRECTIONS)):
        assert derive_cwe("none", r, a, d) is None


def test_every_combination_maps_and_every_corpus_class_is_reachable():
    reached, n = set(), 0
    for m, r, a, d in itertools.product(sorted(MECHANISMS), sorted(REGIONS), sorted(ACCESSES),
                                        sorted(DIRECTIONS)):
        n += 1
        c = derive_cwe(m, r, a, d)
        assert (c is None) == (m == "none"), (m, r, a, d, c)
        if c is None:
            continue
        assert c == AMBIGUOUS or c in CORPUS_CWES, (m, r, a, d, c)
        if c != AMBIGUOUS:
            reached.add(c)
            assert expected_mechanism(c) == m, (m, r, a, d, c)
    assert n == 11 * 5 * 3 * 3
    assert reached == set(CORPUS_CWES)


def test_expected_mechanism_for_every_corpus_class():
    assert {c: expected_mechanism(c) for c in CORPUS_CWES} == {
        "CWE-78": "os_command_injection",
        "CWE-121": "out_of_bounds_access",
        "CWE-122": "out_of_bounds_access",
        "CWE-124": "out_of_bounds_access",
        "CWE-126": "out_of_bounds_access",
        "CWE-127": "out_of_bounds_access",
        "CWE-134": "untrusted_format_string",
        "CWE-190": "integer_overflow",
        "CWE-191": "integer_underflow",
        "CWE-369": "divide_by_zero",
        "CWE-606": "untrusted_loop_bound",
        "CWE-680": "overflowed_size_to_buffer",
        "CWE-789": "untrusted_allocation_size",
    }
    with pytest.raises(ValueError):
        expected_mechanism("CWE-787")


def test_corpus_classes_match_config():
    configured = {f"CWE-{int(str(x).upper().removeprefix('CWE-').removeprefix('CWE'))}"
                  for x in corpus_cfg()["cwes"]}
    assert configured == set(CORPUS_CWES)


def test_unknown_values_fail_closed():
    for fields in [
        ("stack_overflow", "stack", "write", "past_end"),
        ("out_of_bounds_access", "bss", "write", "past_end"),
        ("out_of_bounds_access", "stack", "modify", "past_end"),
        ("out_of_bounds_access", "stack", "write", "sideways"),
    ]:
        with pytest.raises(ValueError):
            derive_cwe(*fields)