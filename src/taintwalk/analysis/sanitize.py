"""Prompt-input sanitation (analysis side).

Phase 3: targeted literal redaction (D-018). A C string literal whose CONTENTS match a
static leak pattern (e.g. Juliet main's "Calling bad()...") is replaced whole by "<str>".
Only literals are touched, and only on a static-pattern match, so format strings and
error messages -- real program evidence -- survive. The leak gate still scans the entire
redacted text afterwards; redaction is not the guarantee, the gate is.

Phase 5: decompiler-noise collapsing (D-016, D-021). Ghidra renders a zero-initialised
local buffer as one store per element (`local_78[0] = '\0';` ... `local_78[99] = '\0';`),
about 20% of all scored lines. A run of MIN_RUN or more consecutive zero stores into the
same buffer becomes one comment that keeps the buffer name, the index range and the count,
because the extent of a buffer is evidence for bounds reasoning. It is a comment, never a
synthesized memset(): an invented call would look like a sink. Applied at prompt
construction only; program.json is never modified (D-016). The two functions are
independent, so literal-redaction counts (the selftest's 960 / 0) cannot move.

Nothing in this module reads ground truth: the patterns are fixed and label-free.
"""
from __future__ import annotations

import re
from typing import NamedTuple

from taintwalk.util.leakcheck import STATIC_PATTERNS

C_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
PLACEHOLDER = '"<str>"'

MIN_RUN = 4
_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
_ZERO = r"(?:0x0|0|'\\0'|'\\x00'|L'\\0'|NULL)"
_INDEX_STORE = re.compile(                                   # local_78[0x5f] = '\0';
    r"^(?P<ind>\s*)(?P<base>[A-Za-z_]\w*)\s*\[\s*(?P<pos>" + _NUM + r")\s*\]"
    r"\s*=\s*" + _ZERO + r"\s*;\s*$"
)
_CAST_STORE = re.compile(                                    # *(undefined8 *)(local_78 + 8) = 0;
    r"^(?P<ind>\s*)\*\s*\(\s*\w+\s*\*\s*\)\s*\(?\s*(?P<base>[A-Za-z_]\w*)"
    r"(?:\s*\+\s*(?P<pos>" + _NUM + r"))?\s*\)?\s*=\s*" + _ZERO + r"\s*;\s*$"
)


class _Store(NamedTuple):
    form: str      # "index" or "offset"
    base: str
    pos: int
    indent: str


def redact_leaky_literals(pseudo_c: str) -> tuple[str, int]:
    """Return (text, number_of_literals_redacted)."""
    count = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal count
        body = m.group(1)
        if any(rx.search(body) for rx in STATIC_PATTERNS.values()):
            count += 1
            return PLACEHOLDER
        return m.group(0)

    return C_STRING.sub(_sub, pseudo_c), count


def _int(s: str | None) -> int:
    if s is None:
        return 0
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def _zero_store(line: str) -> _Store | None:
    m = _INDEX_STORE.match(line)
    if m:
        return _Store("index", m["base"], _int(m["pos"]), m["ind"])
    m = _CAST_STORE.match(line)
    if m:
        return _Store("offset", m["base"], _int(m["pos"]), m["ind"])
    return None


def is_zero_store(line: str) -> bool:
    """True if the line is a single decompiled zero store into a named buffer."""
    return _zero_store(line) is not None


def _marker(first: _Store, positions: list[int], n: int) -> str:
    lo, hi = min(positions), max(positions)
    if first.form == "index":
        where = f"{first.base}[{lo}..{hi}]"
    else:
        where = f"({first.base} + {lo}..{hi})"
    return f"{first.indent}/* {where} = 0: {n} stores collapsed */"


def collapse_decompiler_noise(pseudo_c: str) -> tuple[str, int]:
    """Return (text, number_of_store_lines_collapsed).

    A run is MIN_RUN or more consecutive zero-store lines with the same form and the same
    base buffer. Shorter runs and every other line are kept byte-for-byte, so text with
    no qualifying run comes back unchanged, and the function is idempotent.
    """
    lines = pseudo_c.split("\n")
    out: list[str] = []
    collapsed = 0
    i = 0
    while i < len(lines):
        first = _zero_store(lines[i])
        if first is None:
            out.append(lines[i])
            i += 1
            continue
        positions = [first.pos]
        j = i + 1
        while j < len(lines):
            nxt = _zero_store(lines[j])
            if nxt is None or (nxt.form, nxt.base) != (first.form, first.base):
                break
            positions.append(nxt.pos)
            j += 1
        n = j - i
        if n >= MIN_RUN:
            out.append(_marker(first, positions, n))
            collapsed += n
        else:
            out.extend(lines[i:j])
        i = j
    return "\n".join(out), collapsed