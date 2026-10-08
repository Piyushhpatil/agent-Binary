# (the full agent_sets.py shown above)
"""Phase 10 (D-042): build the dev and scored programs.txt for the agentic run.

Both files use the Phase 9 line format that analysis/walk_all.read_roots already parses:

    <program.json path> 0xaddr,0xaddr

one line per binary, the addresses being that binary's path roots (D-008: the bad/entry root and
every good/path root), sorted numerically by analysis.callgraph.addr_key. A line carries only a
path and hex addresses -- never a name, never a good/bad marker -- so the order of the addresses
cannot reveal which root is which.

This is eval code (SPEC 6: the eval side may read labels), so it reads the manifest's per-function
label and role directly. The dev slice is the 13 Juliet binaries Phase 7 used (tw-0015 plus the 12
shakedown binaries, D-028); the scored slice is every other Juliet binary. The split is fixed here,
so the scored set can never be developed against (D-042).

    python -m taintwalk.eval.agent_sets --out-dir runs/p10
writes runs/p10/dev.programs.txt and runs/p10/scored.programs.txt and prints a one-line summary.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from taintwalk.analysis.callgraph import addr_key
from taintwalk.config import load_config

# The 13 development-slice binaries (D-028): tw-0015 (the Phase 6 gate binary) plus the 12
# shakedown binaries (seed 20260929). Fixed here so the scored set is everything else.
DEV_CASE_IDS = (
    "tw-0015",
    "tw-0151", "tw-0188", "tw-0135", "tw-0175", "tw-0065", "tw-0178",
    "tw-0125", "tw-0237", "tw-0166", "tw-0022", "tw-0066", "tw-0091",
)

# A path root is one of these (label, role) pairs (eval/metrics.ROOT_ROLES, D-008).
ROOT_ROLES = (("bad", "entry"), ("good", "path"))


def _manifest_path(config_path: str | None = None) -> Path:
    cfg = load_config(config_path) if config_path else load_config()
    # The Juliet manifest is the corpus index; its path is the config's corpus.manifest, defaulting
    # to corpus/manifest.json (SPEC 7). load_config resolves it relative to the repo root.
    rel = cfg.get("corpus", {}).get("manifest", "corpus/manifest.json")
    return Path(rel)


def _programs_dir(config_path: str | None = None) -> Path:
    cfg = load_config(config_path) if config_path else load_config()
    return Path(cfg["extract"]["out_dir"]) / "programs"


def root_addrs(entry: dict[str, Any]) -> list[str]:
    """The path-root addresses of one manifest entry, numerically sorted. addr_hex is program.json's
    addr (image base already subtracted, D-016), so it is what a programs.txt line must carry."""
    roles = {(label, role) for (label, role) in ROOT_ROLES}
    addrs = {
        fn["addr_hex"]
        for fn in entry["functions"]
        if (fn.get("label"), fn.get("role")) in roles
    }
    return sorted(addrs, key=addr_key)


def build_sets(
    *,
    manifest_path: Path | None = None,
    programs_dir: Path | None = None,
    config_path: str | None = None,
) -> dict[str, list[str]]:
    """Return {"dev": [...lines...], "scored": [...lines...]}.

    Each line is "<programs_dir>/<case_id>.json 0xa,0xb". An entry with no path root is skipped
    (it would contribute nothing to score); every dev case id must exist, or we fail closed."""
    manifest_path = manifest_path or _manifest_path(config_path)
    programs_dir = programs_dir or _programs_dir(config_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    dev_wanted = set(DEV_CASE_IDS)
    dev: list[str] = []
    scored: list[str] = []
    seen_dev: set[str] = set()

    for entry in manifest["entries"]:
        case_id = entry["case_id"]
        addrs = root_addrs(entry)
        if not addrs:
            continue
        line = f"{programs_dir / f'{case_id}.json'} {','.join(addrs)}"
        if case_id in dev_wanted:
            dev.append(line)
            seen_dev.add(case_id)
        else:
            scored.append(line)

    missing = dev_wanted - seen_dev
    if missing:
        raise ValueError(f"dev-slice case ids not in the manifest: {sorted(missing)}")

    dev.sort()
    scored.sort()
    return {"dev": dev, "scored": scored}


def write_sets(out_dir: Path, sets: dict[str, list[str]]) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "dev": out_dir / "dev.programs.txt",
        "scored": out_dir / "scored.programs.txt",
    }
    for key, path in paths.items():
        path.write_text("\n".join(sets[key]) + "\n", encoding="utf-8")
    return paths


def _count_roots(lines: list[str]) -> int:
    return sum(len(line.split()[1].split(",")) for line in lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taintwalk.eval.agent_sets")
    ap.add_argument("--out-dir", default="runs/p10", type=Path)
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    sets = build_sets(config_path=args.config)
    paths = write_sets(args.out_dir, sets)
    dev_r = _count_roots(sets["dev"])
    scored_r = _count_roots(sets["scored"])
    print(
        f"AGENT SETS OK: dev {len(sets['dev'])} programs / {dev_r} roots, "
        f"scored {len(sets['scored'])} programs / {scored_r} roots, "
        f"total {dev_r + scored_r} roots -> {paths['dev']}, {paths['scored']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())