from __future__ import annotations

import os
import sys
from pathlib import Path

from . import guard as _guard

def _default_ui_workspace():
    home = Path.home()
    return (home / ".safedeps" / "workspace").resolve()

def _is_project_scoped_install():
    return getattr(sys, "base_prefix", sys.prefix) != sys.prefix

def _installation_scope_label():
    return "project" if _is_project_scoped_install() else "system"

class InstallMode:
    def __init__(self, root: Path, label: str | None = None):
        self.root = root
        self.label = (label or _installation_scope_label()).strip().lower()
        if self.label == "global":
            self.label = "system"
        if self.label not in ("project", "system"):
            self.label = "project" if _is_project_scoped_install() else "system"

    @property
    def is_project_install(self) -> bool:
        return self.label == "project"

    @property
    def is_system_install(self) -> bool:
        return self.label == "system"

    @property
    def global_scope_available(self) -> bool:
        return self.is_system_install

    def project_runtime_python(self) -> str | None:
        return _runtime_python_for_project_scope(self.root)

    def system_runtime_python(self) -> str:
        return _runtime_python_for_system_scope()

    def runtime_python_for_action(self, action_scope: str | None = None) -> str:
        scope = str(action_scope or "").strip().lower()
        if self.is_project_install:
            return self.project_runtime_python() or self.system_runtime_python()
        if scope == "project":
            return self.project_runtime_python() or self.system_runtime_python()
        return self.system_runtime_python()

    def action_scope(self, requested_scope: str | None, current_guard_scope: str = "project") -> str:
        scope = str(requested_scope or "").strip().lower()
        if scope not in ("project", "global", "system"):
            scope = str(current_guard_scope or "project").strip().lower()
        if self.is_project_install:
            return "project"
        return "system" if scope in ("global", "system") else "project"

    def enforce_project_state(self, root: Path | None = None):
        if not self.is_project_install:
            return
        target = root or self.root
        state = _load_guard_state(target)
        if str(state.get("protection_scope", "project")).lower() != "project":
            state["protection_scope"] = "project"
            state["project_root"] = str(target)
            _write_guard_state(target, state)

    def can_set_guard_action(self, guard_action: str) -> tuple[bool, str]:
        if self.is_project_install and guard_action == "set_scope_global":
            return False, "Global scope is not available for a SafeDeps virtual environment install."
        return True, ""

def _install_mode(root: Path, label: str | None = None) -> InstallMode:
    return InstallMode(root, label)

def _python_from_virtual_env(venv_root: Path | str):
    base = Path(venv_root)
    if not base.exists() or not base.is_dir():
        return None
    candidates = [
        base / "Scripts" / "python.exe",
        base / "Scripts" / "python",
        base / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None

def _iter_project_runtime_candidates(root: Path):
    def _is_subpath(candidate: Path, base: Path) -> bool:
        try:
            candidate.resolve().relative_to(base.resolve())
            return True
        except ValueError:
            return False

    for venv_name in (".venv-test", "venv", ".venv", "env", ".env", ".virtualenv"):
        py = _python_from_virtual_env(root / venv_name)
        if py:
            yield Path(py)

    active_venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if active_venv:
        py = _python_from_virtual_env(active_venv)
        if py:
            py_path = Path(py)
            project_root = root.resolve()
            if _is_subpath(py_path, project_root):
                yield py_path

def _has_project_runtime_candidates(root: Path) -> bool:
    return any(py is not None for py in _iter_project_runtime_candidates(root))

def _project_runtime_python(root: Path) -> str | None:
    return next((str(py.resolve()) for py in _iter_project_runtime_candidates(root) if py), None)

def _runtime_python_for_project_scope(root: Path) -> str | None:
    return _project_runtime_python(root)

def _runtime_python_for_system_scope() -> str:
    return str(Path(sys.executable).resolve())

def _runtime_python_for_action(root: Path, *, action_scope: str | None = None) -> str:
    return _install_mode(root).runtime_python_for_action(action_scope)

def _detect_project_runtime_python(root: Path):
    # If this process is already running inside a virtual environment, use it.
    if _is_project_scoped_install():
        return str(Path(sys.executable).resolve())

    candidate = _project_runtime_python(root)
    if candidate:
        return candidate

    # Fallback to current executable.
    return str(Path(sys.executable).resolve())

def _looks_like_project_root(path: Path):
    project_markers = [
        ".safedeps",
        "pyproject.toml",
        "requirements.txt",
        "requirements.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Directory.Packages.props",
        "packages.config",
        ".git",
    ]
    if any((path / marker).exists() for marker in project_markers):
        return True
    return any(path.glob("*.csproj"))

def _normalize_project_path(path: Path):
    p = path.resolve()
    if _looks_like_project_root(p):
        return p

    venv_like_names = {
        ".venv",
        ".venv-test",
        "venv",
        ".env",
        "env",
        ".virtualenv",
    }

    if p.name.lower() in venv_like_names:
        parent = p.parent
        if parent != p and _looks_like_project_root(parent):
            return parent
    return p

def _resolve_ui_start_path(path_arg: str):
    raw = (path_arg or "").strip()
    if raw == ".":
        return Path.cwd().resolve()
    if not raw:
        d = _default_ui_workspace()
        d.mkdir(parents=True, exist_ok=True)
        return d
    p = Path(raw).expanduser().resolve()
    return p

