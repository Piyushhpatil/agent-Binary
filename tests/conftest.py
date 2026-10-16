"""Shared test policy (Phase 11, D-043).

Tests tagged @pytest.mark.corpus need the built corpus (runs/p2-extract and the gate runs under runs/).
- Corpus not built (a fresh clone): they are skipped, with a reason that names what is missing.
- Corpus built: they run and fail closed, exactly as before, so a missing gate file is never a silent pass.
The check is made once, when this file is imported, before any test can create files under runs/.
"""
import pytest

from taintwalk.config import REPO_ROOT, load_config

PROGRAMS = REPO_ROOT / load_config()["extract"]["out_dir"] / "programs"
HAVE_CORPUS = PROGRAMS.is_dir()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "corpus: needs the built corpus under runs/; skipped only when it has not been built")


def pytest_collection_modifyitems(config, items):
    if HAVE_CORPUS:
        return
    skip = pytest.mark.skip(
        reason=f"needs the built corpus ({PROGRAMS.relative_to(REPO_ROOT)} is missing); "
               "see README, 'Reproducing the results'")
    for item in items:
        if item.get_closest_marker("corpus"):
            item.add_marker(skip)