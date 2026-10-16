"""Phase 11 (D-043): every three-decimal metric in README.md also appears in docs/RESULTS.md, which the
scorers generate, so the README cannot drift from the scored results. It catches typos and stale numbers;
it cannot tell a real number pasted into the wrong row."""
import re

from taintwalk.config import REPO_ROOT

NUM = re.compile(r"(?<![\d.])0\.\d{3}(?!\d)")


def test_readme_metrics_come_from_results():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    results = (REPO_ROOT / "docs" / "RESULTS.md").read_text(encoding="utf-8")
    nums = sorted(set(NUM.findall(readme)))
    assert len(nums) >= 20, f"expected the README tables to carry at least 20 metrics, found {len(nums)}"
    missing = [n for n in nums if n not in set(NUM.findall(results))]
    assert not missing, f"README metrics not found in docs/RESULTS.md: {missing}"


def test_readme_has_the_section_the_skip_message_points_to():
    assert "\n## Reproducing the results\n" in (REPO_ROOT / "README.md").read_text(encoding="utf-8")