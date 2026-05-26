from __future__ import annotations

import os
from pathlib import Path

from safedeps.models import Finding


class Scanner:
    manager = "generic"

    def scan(self, root: Path, policy) -> tuple[list[Finding], list[dict]]:
        return [], []


SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    ".venv-test",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}


def iter_files(root: Path, filename_pattern: str):
    """Safe recursive file iterator that skips common transient dirs and unreadable paths."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda _e: None):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIR_NAMES and not d.startswith(".venv")
        ]
        base = Path(dirpath)
        for name in filenames:
            if Path(name).match(filename_pattern):
                yield base / name


def path_is_excluded(root: Path, path: Path, policy) -> bool:
    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except Exception:
        rel = str(path).replace("\\", "/")
    excluded = policy.data.get("exclude_paths", []) if getattr(policy, "data", None) else []
    for p in excluded:
        item = str(p or "").strip().replace("\\", "/")
        if not item:
            continue
        if rel == item or rel.startswith(item.rstrip("/") + "/") or rel.startswith(item):
            return True
    return False


def severity_for_exception(policy, manager, pkg, rule, default="HIGH"):
    return "INFO" if policy.has_exception(manager, pkg, rule) else default
