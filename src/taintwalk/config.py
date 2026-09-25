"""Configuration loading for TaintWalk."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# src/taintwalk/config.py -> parents[0]=taintwalk, [1]=src, [2]=repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "default.yaml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load the YAML config (default: config/default.yaml)."""
    cfg_path = path or DEFAULT_CONFIG
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def ghidra_install_dir(cfg: dict[str, Any]) -> Path:
    """Resolve the Ghidra install dir. $GHIDRA_INSTALL_DIR wins over config."""
    raw = os.environ.get("GHIDRA_INSTALL_DIR") or cfg["ghidra"]["install_dir"]
    return Path(os.path.expandvars(os.path.expanduser(raw))).resolve()
