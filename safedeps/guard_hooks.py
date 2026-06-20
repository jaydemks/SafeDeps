from __future__ import annotations

import json
import os
import site
from contextlib import suppress
from pathlib import Path

from .policy import DEFAULT_POLICY


def _init_project(root: Path, force: bool):
    target = root / ".safedeps" / "policy.json"
    if target.exists() and not force:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")

def _site_package_candidates() -> list[Path]:
    candidates: list[Path] = []
    with suppress(Exception):
        candidates.extend(Path(p) for p in site.getsitepackages())
    with suppress(Exception):
        candidates.append(Path(site.getusersitepackages()))
    seen = set()
    out = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            resolved = candidate
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(resolved)
    return sorted(out, key=lambda p: (0 if "site-packages" in str(p).lower().replace("\\", "/") else 1, str(p).lower()))

def _runtime_guard_pth_name() -> str:
    return "zz_safedeps_runtime_guard.pth"

def _runtime_guard_pth_names() -> tuple[str, ...]:
    return ("safedeps_runtime_guard.pth", _runtime_guard_pth_name())

def _runtime_guard_pth_line(root: Path, expected_venv: str, official_repo: str) -> str:
    script = (
        "try:\n"
        " import safedeps.runtime_guard as _safedeps_runtime_guard\n"
        f" _safedeps_runtime_guard.run({str(root)!r}, {expected_venv!r}, {official_repo!r})\n"
        "except ModuleNotFoundError:\n"
        " pass\n"
    )
    return f"import sys; exec({script!r})\n"

def install_interpreter_guard_hook(root: Path, expected_venv: str, official_repo: str) -> Path | None:
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    line = _runtime_guard_pth_line(root, expected_venv, official_repo)
    for site_dir in _site_package_candidates():
        try:
            site_dir.mkdir(parents=True, exist_ok=True)
            target = site_dir / _runtime_guard_pth_name()
            target.write_text(line, encoding="utf-8")
            return target
        except Exception:
            continue
    return None

def remove_interpreter_guard_hook() -> list[Path]:
    removed: list[Path] = []
    for site_dir in _site_package_candidates():
        for name in _runtime_guard_pth_names():
            target = site_dir / name
            try:
                if target.exists():
                    target.unlink()
                    removed.append(target)
            except Exception:
                pass
    return removed
