import json
from types import SimpleNamespace

import safedeps.doctor as doctor


def test_cmd_doctor_reports_manifest_guard_and_toolchain_warnings(tmp_path, monkeypatch, capsys):
    safedeps_dir = tmp_path / ".safedeps"
    safedeps_dir.mkdir()
    (safedeps_dir / "policy.json").write_text(
        json.dumps({"schema": "safedeps.policy.v1", "require_lockfiles": False}),
        encoding="utf-8",
    )
    (safedeps_dir / "metadata-cache.json").write_text(
        json.dumps({"npm": {"demo": {"published": "not-a-date"}}}),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"demo": "1.0.0"}}), encoding="utf-8")
    (tmp_path / "Demo.csproj").write_text("<Project />", encoding="utf-8")

    monkeypatch.setattr(doctor, "get_setup_status", lambda root: "Not configured (pip wrapper missing). Run: safedeps setup .")
    monkeypatch.setattr(doctor, "get_current_shell_guard_status", lambda root: "INACTIVE (wrapper path not found in current PATH).")
    monkeypatch.setattr(doctor, "get_guard_mode_status", lambda root: "OFF now (unless manually activated) | Auto-start OFF | Scope: PROJECT.")
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    monkeypatch.setattr(doctor, "_python_env_warnings", lambda: [])

    assert doctor.cmd_doctor(SimpleNamespace(path=str(tmp_path))) == 0
    out = capsys.readouterr().out

    assert "Status: PASS" in out
    assert "Policy does not require lockfiles" in out
    assert "invalid published date" in out
    assert "package.json found without npm/pnpm/yarn lockfile" in out
    assert ".NET project metadata found without packages.lock.json" in out
    assert "npm project detected but npm is not available" in out
    assert ".NET project detected but dotnet is not available" in out
    assert "Guard setup incomplete" in out
    assert "Current shell guard inactive" in out
    assert "Auto guard inactive" in out


def test_cmd_doctor_fails_on_invalid_policy_shape(tmp_path, monkeypatch, capsys):
    safedeps_dir = tmp_path / ".safedeps"
    safedeps_dir.mkdir()
    (safedeps_dir / "policy.json").write_text(
        json.dumps({"allowed_registries": [], "deny_packages": {}, "exceptions": {}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(doctor, "_python_env_warnings", lambda: [])

    assert doctor.cmd_doctor(SimpleNamespace(path=str(tmp_path))) == 2
    out = capsys.readouterr().out

    assert "policy.allowed_registries must be an object" in out
    assert "policy.deny_packages must be a list" in out
    assert "policy.exceptions must be a list" in out


def test_cmd_doctor_reports_invalid_policy_values(tmp_path, monkeypatch, capsys):
    safedeps_dir = tmp_path / ".safedeps"
    safedeps_dir.mkdir()
    (safedeps_dir / "policy.json").write_text(
        json.dumps(
            {
                "schema": "safedeps.policy.v1",
                "allowed_registries": {"npm": [123]},
                "allow_unpinned": "false",
                "require_lockfiles": "true",
                "min_package_age_days": "14",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(doctor, "_python_env_warnings", lambda: [])

    assert doctor.cmd_doctor(SimpleNamespace(path=str(tmp_path))) == 2
    out = capsys.readouterr().out

    assert "policy.allowed_registries.npm[0] must be a non-empty string" in out
    assert "policy.allow_unpinned must be true or false" in out
    assert "policy.require_lockfiles must be true or false" in out
    assert "policy.min_package_age_days must be a non-negative integer" in out


def test_cmd_doctor_reports_invalid_metadata_shape(tmp_path, monkeypatch, capsys):
    safedeps_dir = tmp_path / ".safedeps"
    safedeps_dir.mkdir()
    (safedeps_dir / "policy.json").write_text(json.dumps({"schema": "safedeps.policy.v1"}), encoding="utf-8")
    (safedeps_dir / "metadata-cache.json").write_text(json.dumps({"pip": {"demo": "bad"}}), encoding="utf-8")
    monkeypatch.setattr(doctor, "_python_env_warnings", lambda: [])

    assert doctor.cmd_doctor(SimpleNamespace(path=str(tmp_path))) == 0
    out = capsys.readouterr().out

    assert "metadata-cache.json entry pip/demo should be an object" in out


def test_project_health_warnings_cover_python_and_empty_paths(tmp_path):
    assert any("No known dependency manifest detected" in warning for warning in doctor._project_health_warnings(tmp_path))

    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    warnings = doctor._project_health_warnings(tmp_path)

    assert "Python requirements.txt found without requirements.lock." in warnings
    assert "pyproject.toml found without uv.lock, poetry.lock, or requirements.lock." in warnings


def test_python_env_warnings_handles_pytest_failures(monkeypatch):
    class FailedProc:
        returncode = 1

    monkeypatch.setattr(doctor.subprocess, "run", lambda *args, **kwargs: FailedProc())
    warnings = doctor._python_env_warnings()

    assert any("pytest is not available" in warning for warning in warnings)

    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert any("pytest check unavailable" in warning for warning in doctor._python_env_warnings())
