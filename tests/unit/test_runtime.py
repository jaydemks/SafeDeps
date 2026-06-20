from pathlib import Path

import safedeps.runtime as runtime


def _write_executable(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def test_python_from_virtual_env_prefers_windows_scripts_layout(tmp_path):
    py = tmp_path / "Scripts" / "python.exe"
    _write_executable(py)

    assert runtime._python_from_virtual_env(tmp_path) == str(py)


def test_python_from_virtual_env_falls_back_to_posix_layout(tmp_path):
    py = tmp_path / "bin" / "python"
    _write_executable(py)

    assert runtime._python_from_virtual_env(tmp_path) == str(py)


def test_iter_project_runtime_candidates_includes_project_virtualenv(tmp_path, monkeypatch):
    py = tmp_path / ".venv" / "bin" / "python"
    _write_executable(py)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)

    assert list(runtime._iter_project_runtime_candidates(tmp_path)) == [py]


def test_iter_project_runtime_candidates_ignores_external_active_virtualenv(tmp_path, monkeypatch):
    external = tmp_path.parent / "external-venv" / "bin" / "python"
    _write_executable(external)
    monkeypatch.setenv("VIRTUAL_ENV", str(external.parent.parent))

    assert list(runtime._iter_project_runtime_candidates(tmp_path)) == []


def test_install_mode_normalizes_global_to_system(tmp_path):
    mode = runtime.InstallMode(tmp_path, "global")

    assert mode.label == "system"
    assert mode.global_scope_available
    assert mode.action_scope("global") == "system"


def test_project_install_mode_forces_project_actions(tmp_path):
    mode = runtime.InstallMode(tmp_path, "project")

    allowed, reason = mode.can_set_guard_action("set_scope_global")

    assert mode.action_scope("global", current_guard_scope="system") == "project"
    assert not allowed
    assert "Global scope" in reason
