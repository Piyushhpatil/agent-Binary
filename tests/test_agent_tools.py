"""Phase 10 agent tools (D-042) on a synthetic program: scope, statuses, preparation, refusals."""
import pytest

from taintwalk.analysis.agent_tools import (
    TRUNC_MARK, ToolError, list_callees, make_scope, read_code, read_summary,
)
from taintwalk.analysis.prompts import prepare_code

SHA = "0" * 64
BODY = "void f(void)\n{\n  return;\n}"


def _fn(addr, name, callees=(), *, pseudo_c=BODY, in_scope=True, failed=False):
    return {
        "addr": addr, "ghidra_name": name, "in_scope": in_scope, "decompile_failed": failed,
        "pseudo_c": None if failed else pseudo_c,
        "callees": [{"kind": "internal", "addr": c, "name": None, "via_thunk": None} for c in callees]
                   + [{"kind": "external", "addr": None, "name": "puts", "via_thunk": "0x5060"}],
    }


PROG = {"binary": {"sha256": SHA}, "functions": [
    _fn("0x1000", "FUN_00101000", ("0x1100", "0x1200", "0x1500")),
    _fn("0x1100", "FUN_00101100", ("0x1300",), pseudo_c="int g(int param_1)\n{\n  return param_1 + 1;\n}"),
    _fn("0x1200", "FUN_00101200", failed=True),
    _fn("0x1300", "FUN_00101300"),
    _fn("0x1400", "FUN_00101400"),                       # in scope, not reachable from 0x1000
    _fn("0x1500", "FUN_00101500", in_scope=False),       # excluded by the extractor
]}


class _NoCalls:
    """A provider stand-in that fails the test if anything reaches it."""
    def complete(self, *a, **k):
        raise AssertionError("no model call expected")

    def identity(self):
        raise AssertionError("no model call expected")


def test_scope_is_the_downward_closure():
    s = make_scope(PROG, "0x1000")
    assert s.closure == frozenset({"0x1000", "0x1100", "0x1200", "0x1300"})
    with pytest.raises(ValueError):
        make_scope(PROG, "0x1500")


def test_list_callees_statuses_in_address_order():
    s = make_scope(PROG, "0x1000")
    assert list_callees(s, "0x1000") == [
        {"addr": "0x1100", "name": "FUN_00101100", "status": "readable"},
        {"addr": "0x1200", "name": "FUN_00101200", "status": "no_code"},
        {"addr": "0x1500", "name": "FUN_00101500", "status": "out_of_scope"},
    ]
    assert list_callees(s, "0x1300") == []


def test_list_callees_outside_scope_is_refused():
    with pytest.raises(ToolError):
        list_callees(make_scope(PROG, "0x1100"), "0x1000")     # a caller is outside 0x1100's closure


def test_read_code_is_prepared_and_unnumbered():
    text = read_code(make_scope(PROG, "0x1000"), "0x1100", max_chars=4000)
    assert text == "\n".join(prepare_code(PROG["functions"][1]["pseudo_c"])[0])
    assert "return param_1 + 1;" in text


def test_read_code_refusals():
    s = make_scope(PROG, "0x1000")
    for addr in ("0x1000", "0x1400", "0x1500", "0x1200"):   # root, unreachable, excluded, no code
        with pytest.raises(ToolError):
            read_code(s, addr, max_chars=4000)


def test_read_code_cuts_at_whole_lines():
    body = "void h(void)\n{\n" + "".join(f"  local_{i:03d} = {i};\n" for i in range(200)) + "}"
    prog = {"binary": {"sha256": SHA}, "functions": [
        _fn("0x1000", "FUN_00101000", ("0x1100",)), _fn("0x1100", "FUN_00101100", pseudo_c=body)]}
    full = "\n".join(prepare_code(body)[0])
    text = read_code(make_scope(prog, "0x1000"), "0x1100", max_chars=100)
    shown, marker = text.rsplit("\n", 1)
    assert 0 < len(shown) <= 100 and full.startswith(shown + "\n")
    assert marker == TRUNC_MARK.format(n=len(full) - len(shown))


def test_read_summary_without_code_makes_no_call(tmp_path):
    view, row = read_summary(_NoCalls(), make_scope(PROG, "0x1000"), "0x1200", tmp_path)
    assert (view.status, view.summary, row) == ("decompile_failed", None, None)
    assert not any(tmp_path.iterdir())


def test_read_summary_refusals_come_before_any_call(tmp_path):
    s = make_scope(PROG, "0x1000")
    for addr in ("0x1000", "0x1400"):
        with pytest.raises(ToolError):
            read_summary(_NoCalls(), s, addr, tmp_path)
    assert not any(tmp_path.iterdir())
