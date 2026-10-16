"""Phase 11 (D-043): every repo path docs/ARCHITECTURE.md names exists, so the doc cannot quietly rot.

Hermetic: only committed locations are checked (src/, scripts/, tests/, config/, docs/, corpus/*.json).
"""
import re

from taintwalk.config import REPO_ROOT

DOC = REPO_ROOT / "docs" / "ARCHITECTURE.md"
PATH = re.compile(r"`((?:src|scripts|tests|config|docs)/[\w./-]+|corpus/[\w/-]+\.json)`")


def test_architecture_doc_names_only_real_paths():
    named = sorted(set(PATH.findall(DOC.read_text(encoding="utf-8"))))
    assert len(named) >= 20, f"expected the doc to name at least 20 paths, found {len(named)}"
    missing = [p for p in named if not (REPO_ROOT / p).exists()]
    assert not missing, f"ARCHITECTURE.md names paths that do not exist: {missing}"


def test_architecture_doc_has_a_mermaid_diagram():
    assert "```mermaid" in DOC.read_text(encoding="utf-8")