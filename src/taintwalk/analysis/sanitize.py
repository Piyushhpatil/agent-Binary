"""Prompt-input sanitation (analysis side).

Phase 3: targeted literal redaction (D-018). A C string literal whose CONTENTS match a
static leak pattern (e.g. Juliet main's "Calling bad()...") is replaced whole by "<str>".
Only literals are touched, and only on a static-pattern match, so format strings and
error messages -- real program evidence -- survive. The leak gate still scans the entire
redacted text afterwards; redaction is not the guarantee, the gate is.

Phase 5 adds decompiler-noise collapsing here (D-016). Nothing in this module reads
ground truth: the patterns are fixed and label-free.
"""
from __future__ import annotations

import re

from taintwalk.util.leakcheck import STATIC_PATTERNS

C_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
PLACEHOLDER = '"<str>"'


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