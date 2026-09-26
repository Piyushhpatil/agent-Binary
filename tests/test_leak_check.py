"""Leak gate (I1). Includes deliberately leaking prompts that MUST be rejected."""
from __future__ import annotations

import pytest

from taintwalk.analysis.sanitize import PLACEHOLDER, redact_leaky_literals
from taintwalk.util.leakcheck import LeakCheckConfigError, LeakError, assert_clean, scan

# tw-0001 (committed manifest). Its stripped sha is what program.json carries.
TW0001_SHA = "07510add94cd25f95eace56af1570d59265085e869cbf6bf4944aaf61cd2fac4"

# tw-0001 main (0x1d3e), verbatim from runs/p2-smoke/program.json.
TW0001_MAIN = r"""
undefined8 FUN_00101d3e(void)

{
  time_t tVar1;
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  FUN_001013c9("Calling good()...");
  FUN_00101d2e();
  FUN_001013c9("Finished good()");
  FUN_001013c9("Calling bad()...");
  FUN_001019dd();
  FUN_001013c9("Finished bad()");
  return 0;
}
"""

CLEAN = r"""
void FUN_001019dd(void)
{
  char local_78 [104];
  ssize_t sVar1;
  sVar1 = recv(iVar2,local_78,99,0);
  strcpy(local_48,local_78);
  printf("%s\n",local_78);
  FUN_001013c9("ERROR: Array index is negative.");
  return;
}
"""


def test_clean_passes_static_layer():
    assert_clean(CLEAN)


def test_clean_passes_name_layer():
    assert_clean(CLEAN, TW0001_SHA)


def test_import_names_are_not_leaks():
    assert_clean("/* imports: execlp, fgets, memcpy, printf, recv, strcpy */", TW0001_SHA)


def test_main_is_not_denylisted():
    assert_clean("int main(void) { return 0; }", TW0001_SHA)


@pytest.mark.parametrize("leaky", [
    "/* CWE121 */",
    "cwe-78 injection",
    'FUN_001013c9("Calling bad()...");',
    "CWE78_OS_Command_Injection__char_connect_socket_execlp_01_bad();",
    "goodG2B();",
    "x = goodB2G1;",
    "defined in io.c",
    "from the Juliet suite",
    "#ifndef OMITBAD",
])
def test_static_layer_rejects(leaky):
    with pytest.raises(LeakError) as ei:
        assert_clean(leaky)
    assert all(f.layer == "static" for f in ei.value.findings)


@pytest.mark.parametrize("leaky", [
    "FUN_1(); /* printLine */",
    "decodeHexChars(p, n);",
    "globalReturnsTrue",
])
def test_name_layer_rejects_what_static_misses(leaky):
    assert scan(leaky) == []                       # static layer alone is blind to these
    with pytest.raises(LeakError) as ei:
        assert_clean(leaky, TW0001_SHA)
    assert any(f.layer == "name" for f in ei.value.findings)


def test_unknown_binary_fails_closed():
    with pytest.raises(LeakCheckConfigError):
        assert_clean(CLEAN, "0" * 64)


def test_error_message_is_loud_and_specific():
    with pytest.raises(LeakError) as ei:
        assert_clean('FUN_1("Calling bad()...");')
    msg = str(ei.value)
    assert "GROUND-TRUTH LEAK" in msg and "call_form" in msg


def test_real_main_is_rejected_raw():
    with pytest.raises(LeakError):
        assert_clean(TW0001_MAIN, TW0001_SHA)


def test_real_main_passes_after_redaction():
    red, n = redact_leaky_literals(TW0001_MAIN)
    assert n == 4
    assert red.count(PLACEHOLDER) == 4
    assert "FUN_00101d2e();" in red and "FUN_001019dd();" in red   # structure intact
    assert_clean(red, TW0001_SHA)


def test_redaction_leaves_real_evidence_alone():
    red, n = redact_leaky_literals(CLEAN)
    assert n == 0 and red == CLEAN                 # format string + sanitizer message kept