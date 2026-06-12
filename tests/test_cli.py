import pytest
import json
import re
import subprocess
import sys
from pathlib import Path
import safedeps.cli as cli_mod
import safedeps.guard as guard_mod
import safedeps.runtime_guard as runtime_guard_mod
from safedeps.guard import _filter_guard_path_entries, _strip_autoguard_blocks, _strip_cmd_autorun_blocks
from safedeps.cli import (
    main,
    render_ui_page,
    render_dependency_table,
    _resolve_ui_start_path,
    _is_project_scoped_install,
    _normalize_project_path,
    _iter_project_runtime_candidates,
    _has_project_runtime_candidates,
    _detect_project_runtime_python,
    _install_mode,
    _project_runtime_python,
    collect_runtime_components,
    apply_dependency_action,
)
from safedeps import __version__
from safedeps.models import ScanResult, Finding
from safedeps.scanners import yaml as scanners_yaml


def test_bad_project_fails():
    code = main(["scan", "examples/bad-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_safe_project_passes():
    code = main(["scan", "examples/safe-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_pyproject_unpinned_dependency_fails(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "0.0.1"
dependencies = ["requests>=2.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "allow_unpinned": False,
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pyproject_pinned_dependency_passes(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "0.0.1"
dependencies = ["requests==2.32.3"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "allow_unpinned": False,
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_poetry_lock_denylist_fails(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_uv_lock_denylist_fails(tmp_path):
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pipfile_lock_denylist_fails(tmp_path):
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "requests": {"version": "==2.32.3"},
                },
                "develop": {},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pipfile_lock_invalid_reports_high(tmp_path):
    (tmp_path / "Pipfile.lock").write_text("{ invalid json", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_package_lock_denylist_fails(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo-node", "version": "1.0.0"},
                    "node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_package_lock_invalid_reports_high(tmp_path):
    (tmp_path / "package-lock.json").write_text("{ invalid json", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pnpm_lock_denylist_or_parser_warning(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text(
        """
lockfileVersion: '9.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-demo}
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    if scanners_yaml is None:
        assert code == 0
    else:
        assert code == 2


def test_pnpm_lock_invalid_reports_high_when_yaml_available(tmp_path):
    if scanners_yaml is None:
        return
    (tmp_path / "pnpm-lock.yaml").write_text(":\n  bad", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

def test_ui_page_renders_findings():
    result = ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="HIGH",
                manager="npm",
                rule="FLOATING_VERSION",
                message="demo",
                package="lodash",
                file="package.json",
            )
        ],
        sbom={"components": [{"name": "lodash", "version": "1.0.0", "manager": "npm"}]},
    )
    page = render_ui_page(Path(".").resolve(), "HIGH", result=result, outdir=Path("security-artifacts"))
    assert "SafeDeps UI" in page
    assert "FLOATING_VERSION" in page
    assert "package.json" in page
    assert "Use For Approval" in page


def test_render_dependency_table_project_scope_excludes_runtime(tmp_path):
    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "npm", "name": "demo-project", "version": "1.0.0", "scope": "dependencies"},
                {"type": "library", "manager": "pip", "name": "runtime-system", "version": "9.9.9", "scope": "runtime:pip"},
            ]
        },
    )
    table = render_dependency_table(result, "HIGH", tmp_path, "project", installation_scope="project")
    assert "Project dependencies" in table
    assert "Project runtime dependencies" not in table
    assert "System/runtime dependencies" not in table
    assert "demo-project" in table
    assert "runtime-system" not in table


def test_detect_project_runtime_python_uses_project_virtual_env(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "prefix", "/tmp/system", raising=False)
    monkeypatch.setattr(sys, "base_prefix", "/tmp/system", raising=False)

    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    python_path = venv / "python"
    python_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    python_path.chmod(0o755)

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    detected = _detect_project_runtime_python(tmp_path)
    assert detected == str(python_path.resolve())


def test_project_runtime_candidates_ignores_external_active_venv(tmp_path, monkeypatch):
    project_root = tmp_path / "project"
    project_root.mkdir()
    external_root = tmp_path / "external"
    external_root.mkdir()
    external_venv = external_root / "venv" / "bin"
    external_venv.mkdir(parents=True)
    external_python = external_venv / "python"
    external_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    external_python.chmod(0o755)

    monkeypatch.setenv("VIRTUAL_ENV", str(external_root / "venv"))

    assert not (project_root / ".venv").exists()
    assert _project_runtime_python(project_root) is None


def test_collect_runtime_components_timeout_does_not_block_ui(tmp_path, monkeypatch):
    from safedeps import cli as cli_mod

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args=args[0], timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(cli_mod.subprocess, "run", fake_run)

    assert collect_runtime_components(
        tmp_path,
        python_executable="python",
        runtime_scope="runtime:system",
        fallback_to_process=False,
    ) == []


def test_project_install_mode_forces_project_only_behavior(tmp_path, monkeypatch):
    from safedeps import cli as cli_mod

    project_python = tmp_path / ".venv" / "bin" / "python"
    project_python.parent.mkdir(parents=True)
    project_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    project_python.chmod(0o755)
    system_python = tmp_path / "system-python"
    system_python.write_text("", encoding="utf-8")

    monkeypatch.setattr(cli_mod, "_runtime_python_for_system_scope", lambda: str(system_python))

    mode = _install_mode(tmp_path, "project")

    assert mode.is_project_install
    assert not mode.global_scope_available
    assert mode.action_scope("global", "global") == "project"
    assert mode.runtime_python_for_action("global") == str(project_python.resolve())
    assert mode.can_set_guard_action("set_scope_global")[0] is False


def test_system_install_mode_keeps_project_and_global_behavior_separate(tmp_path, monkeypatch):
    from safedeps import cli as cli_mod

    project_python = tmp_path / ".venv" / "bin" / "python"
    project_python.parent.mkdir(parents=True)
    project_python.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    project_python.chmod(0o755)
    system_python = tmp_path / "system-python"
    system_python.write_text("", encoding="utf-8")

    monkeypatch.setattr(cli_mod, "_runtime_python_for_system_scope", lambda: str(system_python))

    mode = _install_mode(tmp_path, "system")

    assert mode.is_system_install
    assert mode.global_scope_available
    assert mode.action_scope("project", "global") == "project"
    assert mode.action_scope("global", "project") == "system"
    assert mode.runtime_python_for_action("project") == str(project_python.resolve())
    assert mode.runtime_python_for_action("global") == str(system_python)
    assert mode.can_set_guard_action("set_scope_global")[0] is True


def test_guard_toggle_allows_global_when_install_scope_is_system(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "prefix", str(tmp_path / ".venv"))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "base"))

    msg = cli_mod.apply_guard_toggle(tmp_path, "set_scope_global", install_scope="system")
    saved = json.loads((tmp_path / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))

    assert "GLOBAL" in msg
    assert saved["auto_guard"] is False
    assert saved["protection_scope"] == "global"


def test_guard_toggle_forces_project_when_install_scope_is_project(tmp_path):
    msg = cli_mod.apply_guard_toggle(tmp_path, "set_scope_global", install_scope="project")
    saved = json.loads((tmp_path / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))

    assert "not available" in msg
    assert saved["auto_guard"] is False
    assert saved["protection_scope"] == "project"


def test_ui_render_install_scope_system_keeps_global_toggle_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "prefix", str(tmp_path / ".venv"))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "base"))

    page = render_ui_page(tmp_path, "HIGH", install_scope="system")
    global_button = re.search(r'<button[^>]+value="set_scope_global"[^>]*>', page)

    assert global_button
    assert "disabled" not in global_button.group(0)
    assert "Global scope is locked" not in page


def test_render_dependency_table_system_scope_shows_project_runtime_if_detected(tmp_path, monkeypatch):
    from safedeps import cli as cli_mod

    venv = tmp_path / ".venv-test" / "bin"
    venv.mkdir(parents=True)
    python_path = venv / "python"
    python_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    python_path.chmod(0o755)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")

    calls = []

    def fake_collect_runtime_components(root, **kwargs):
        calls.append(kwargs)
        runtime_scope = str(kwargs.get("runtime_scope", ""))
        if runtime_scope.startswith("runtime:project"):
            return [
                {"type":"library","manager":"pip","name":"project-runtime","version":"9.9.9","scope":"runtime:project:pip"}
            ]
        if runtime_scope.startswith("runtime:system"):
            return [
                {"type":"library","manager":"pip","name":"system-runtime","version":"3.11.0","scope":"runtime:system:pip"}
            ]
        return []

    monkeypatch.setattr(cli_mod, "collect_runtime_components", fake_collect_runtime_components)

    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "pip", "name": "project-dep", "version": "1.0.0", "scope": "dependencies"},
            ]
        },
    )
    table = render_dependency_table(result, "HIGH", tmp_path, "project", installation_scope="system")
    assert "Project dependencies" in table
    assert "Project runtime dependencies" in table
    assert "System/runtime dependencies" in table
    assert "project-dep" in table
    assert "project-runtime" in table
    assert "system-runtime" in table


def test_render_dependency_table_global_scope_splits_sections():
    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "npm", "name": "demo-project", "version": "1.0.0", "scope": "dependencies"},
                {"type": "library", "manager": "pip", "name": "runtime-system", "version": "9.9.9", "scope": "runtime:pip"},
            ]
        },
    )
    table = render_dependency_table(result, "HIGH", Path("."), "global", installation_scope="system")
    assert "Project dependencies" in table
    assert "System/runtime dependencies" in table
    assert "demo-project" in table
    assert "runtime-system" in table


def test_render_dependency_table_keeps_separate_runtime_scopes_for_same_package(tmp_path):
    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {
                    "type": "library",
                    "manager": "pip",
                    "name": "colorama",
                    "version": "0.4.6",
                    "scope": "runtime:project:pip",
                },
                {
                    "type": "library",
                    "manager": "pip",
                    "name": "colorama",
                    "version": "0.4.5",
                    "scope": "runtime:system:pip",
                },
            ]
        },
    )

    table = render_dependency_table(result, "HIGH", tmp_path, "project", installation_scope="system")
    assert "data-scope=\"runtime:project:pip\"" in table
    assert "data-scope=\"runtime:system:pip\"" in table
    assert "data-runtime-scope=\"project\"" in table
    assert "data-runtime-scope=\"system\"" in table
    assert table.count("data-package=\"colorama\"") >= 2


def test_render_dependency_table_project_install_merges_declared_and_installed_versions(tmp_path):
    result = ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="HIGH",
                manager="pip",
                rule="UNPINNED_VERSION",
                message="Unpinned pip dependency: pytest>=8.0",
                package="pytest",
                file="pyproject.toml",
            )
        ],
        sbom={
            "components": [
                {
                    "type": "library",
                    "manager": "pip",
                    "name": "pytest",
                    "version": ">=8.0",
                    "scope": "dependencies",
                },
                {
                    "type": "library",
                    "manager": "pip",
                    "name": "pytest",
                    "version": "9.0.3",
                    "scope": "runtime:project:pip",
                },
            ]
        },
    )

    table = render_dependency_table(result, "HIGH", tmp_path, "project", installation_scope="project")

    assert table.count("data-package=\"pytest\"") == 1
    assert "<th>Declared</th><th>Installed</th>" in table
    assert "&gt;=8.0" in table
    assert "9.0.3" in table
    assert "UNPINNED_VERSION" in table


def test_apply_dependency_action_targets_project_runtime_when_scope_passed(monkeypatch, tmp_path):
    project_python = tmp_path / "project_py.exe"
    project_python.write_text("", encoding="utf-8")
    system_python = tmp_path / "system_py.exe"
    system_python.write_text("", encoding="utf-8")

    def fake_scan_pipeline(root, policy_arg, out, fail_on, online_audit, sarif, cyclonedx, spdx, html):
        outdir = root / out
        outdir.mkdir(parents=True, exist_ok=True)
        return ScanResult(ok=True, findings=[], sbom={"components": []}), outdir

    calls = []

    def fake_run_cmd(args, cwd):
        calls.append(args)
        return 0, ""

    monkeypatch.setattr(cli_mod, "run_scan_pipeline", fake_scan_pipeline)
    monkeypatch.setattr(cli_mod, "_run_cmd", fake_run_cmd)
    monkeypatch.setattr(cli_mod, "_runtime_python_for_project_scope", lambda root: str(project_python))
    monkeypatch.setattr(cli_mod, "_runtime_python_for_system_scope", lambda: str(system_python))

    apply_dependency_action(
        root=tmp_path,
        manager="pip",
        action="uninstall",
        package="colorama",
        version="",
        mode="manual",
        approved=False,
        approval_note="",
        action_scope="project",
    )

    assert calls, calls
    assert any(call[0] == str(project_python) and call[1:4] == ["-m", "pip", "uninstall"] for call in calls)


def test_apply_dependency_action_uninstall_blocks_required_pip_package(monkeypatch, tmp_path):
    project_python = tmp_path / "project_py.exe"
    project_python.write_text("", encoding="utf-8")

    def fake_scan_pipeline(root, policy_arg, out, fail_on, online_audit, sarif, cyclonedx, spdx, html):
        outdir = root / out
        outdir.mkdir(parents=True, exist_ok=True)
        return ScanResult(ok=True, findings=[], sbom={"components": []}), outdir

    calls = []

    def fake_run_cmd(args, cwd):
        calls.append(args)
        cmd = " ".join(str(x) for x in args)
        if "-m pip show colorama" in cmd:
            return 0, "Name: colorama\nVersion: 0.4.6\nRequired-by: pytest"
        return 0, ""

    monkeypatch.setattr(cli_mod, "run_scan_pipeline", fake_scan_pipeline)
    monkeypatch.setattr(cli_mod, "_run_cmd", fake_run_cmd)
    monkeypatch.setattr(cli_mod, "_runtime_python_for_project_scope", lambda root: str(project_python))
    monkeypatch.setattr(cli_mod, "_runtime_python_for_system_scope", lambda: str(project_python))

    with pytest.raises(ValueError, match="required by installed package"):
        apply_dependency_action(
            root=tmp_path,
            manager="pip",
            action="uninstall",
            package="colorama",
            version="",
            mode="manual",
            approved=False,
            approval_note="",
            action_scope="project",
        )

    assert not any(call[1:4] == ["-m", "pip", "uninstall"] for call in calls)


def test_apply_dependency_action_uninstall_reports_scope_miss(monkeypatch, tmp_path):
    project_python = tmp_path / "project_py.exe"
    project_python.write_text("", encoding="utf-8")

    def fake_scan_pipeline(root, policy_arg, out, fail_on, online_audit, sarif, cyclonedx, spdx, html):
        outdir = root / out
        outdir.mkdir(parents=True, exist_ok=True)
        return ScanResult(ok=True, findings=[], sbom={"components": []}), outdir

    def fake_run_cmd(args, cwd):
        cmd = " ".join(str(x) for x in args)
        if "-m pip show colorama" in cmd:
            return 0, ""
        return 0, "Skipping colorama as it is not installed."

    monkeypatch.setattr(cli_mod, "run_scan_pipeline", fake_scan_pipeline)
    monkeypatch.setattr(cli_mod, "_run_cmd", fake_run_cmd)
    monkeypatch.setattr(cli_mod, "_runtime_python_for_project_scope", lambda root: str(project_python))
    monkeypatch.setattr(cli_mod, "_runtime_python_for_system_scope", lambda: str(project_python))

    with pytest.raises(ValueError, match="not installed in the selected"):
        apply_dependency_action(
            root=tmp_path,
            manager="pip",
            action="uninstall",
            package="colorama",
            version="",
            mode="manual",
            approved=False,
            approval_note="",
            action_scope="project",
        )


def test_render_dependency_table_project_scope_includes_runtime_for_venv_install(tmp_path, monkeypatch):
    from safedeps import cli as cli_mod

    venv = tmp_path / ".venv" / "Scripts"
    venv.mkdir(parents=True)
    python_path = venv / "python.exe"
    python_path.write_text("#!python\n", encoding="utf-8")
    monkeypatch.setattr(
        cli_mod,
        "collect_runtime_components",
        lambda root, **kwargs: [{"type":"library","manager":"pip","name":"runtime-system","version":"9.9.9","scope":"runtime:project:pip"}],
    )

    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "pip", "name": "project-dep", "version": "1.0.0", "scope": "dependencies"},
            ]
        },
    )
    table = render_dependency_table(result, "HIGH", tmp_path, "project", installation_scope="project")
    assert "Project dependencies" in table
    assert "Project runtime dependencies" not in table
    assert "System/runtime dependencies" not in table
    assert "project-dep" in table
    assert "runtime-system" in table


def test_version_commands(capsys):
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_ui_start_path_uses_workspace_without_explicit_path(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname = \"demo\"\nversion = \"0.0.1\"\n", encoding="utf-8")
    assert _resolve_ui_start_path("") == (home / ".safedeps" / "workspace").resolve()
    assert _resolve_ui_start_path(".") == tmp_path.resolve()


def test_ui_start_path_prefers_current_dir_in_project_scoped_install(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "pyproject.toml").exists()
    monkeypatch.setattr(sys, "base_prefix", "/tmp/fake-system-base")
    assert _is_project_scoped_install()


def test_normalize_project_path_keeps_project_root(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0.0'\n", encoding="utf-8")
    assert _normalize_project_path(tmp_path) == tmp_path


def test_normalize_project_path_moves_from_venv_to_parent(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0.0'\n", encoding="utf-8")
    venv_dir = tmp_path / ".venv-test"
    venv_dir.mkdir()
    monkeypatch.chdir(venv_dir)
    assert _normalize_project_path(venv_dir) == tmp_path
    assert _resolve_ui_start_path("") == (home / ".safedeps" / "workspace").resolve()
    assert _normalize_project_path(_resolve_ui_start_path(".")) == tmp_path.resolve()


def test_ui_start_path_falls_back_to_workspace_outside_project(tmp_path, monkeypatch):
    home = tmp_path / "home"
    cwd = tmp_path / "empty"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(cwd)
    assert _resolve_ui_start_path("") == (home / ".safedeps" / "workspace").resolve()


def test_setup_forces_project_scope_for_venv_install(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    state = root / ".safedeps" / "guard-state.json"
    state.parent.mkdir()
    state.write_text(
        json.dumps(
            {
                "protection_scope": "global",
                "project_root": str(tmp_path),
                "auto_guard_powershell": False,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(sys, "prefix", str(root / ".venv"))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "python-base"))

    code = main(["setup", str(root)])
    assert code == 0
    saved = json.loads((root / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))
    assert saved["auto_guard"] is False
    assert saved["protection_scope"] == "project"
    assert saved["project_root"] == str(root)


def test_yarn_lock_denylist_fails(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        """
"lodash@^4.17.0":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-demo
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_yarn_lock_scoped_denylist_fails(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        """
"@types/node@^20.0.0":
  version "20.14.10"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.14.10.tgz"
  integrity sha512-demo
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["@types/node"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_directory_packages_props_denylist_fails(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        """
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_config_denylist_fails(tmp_path):
    (tmp_path / "packages.config").write_text(
        """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net8.0" />
</packages>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_directory_packages_props_invalid_reports_high(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text("<Project><ItemGroup>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_lock_json_denylist_fails(tmp_path):
    (tmp_path / "packages.lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "dependencies": {
                    ".NETCoreApp,Version=v8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "requested": "[13.0.3, )",
                            "resolved": "13.0.3",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "Demo.csproj").write_text("<Project/>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_lock_json_invalid_reports_high(tmp_path):
    (tmp_path / "packages.lock.json").write_text("{ invalid", encoding="utf-8")
    (tmp_path / "Demo.csproj").write_text("<Project/>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_monorepo_root_lockfile_covers_workspace_package(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "root", "lockfileVersion": 3, "packages": {"": {"name": "root", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    ws = tmp_path / "packages" / "app1"
    ws.mkdir(parents=True)
    (ws / "package.json").write_text(json.dumps({"name": "app1", "version": "1.0.0"}), encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"require_lockfiles": True}), encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_monorepo_workspace_without_lockfile_reports_missing(tmp_path):
    ws = tmp_path / "packages" / "app1"
    ws.mkdir(parents=True)
    (ws / "package.json").write_text(json.dumps({"name": "app1", "version": "1.0.0"}), encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"require_lockfiles": True}), encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0
    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    assert any(f.get("rule") == "MISSING_LOCKFILE" and f.get("manager") == "npm" for f in report.get("findings", []))


def test_typosquatting_risk_for_pip_dependency_reports_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text("reqests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("reqests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": True,
                "protected_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_typosquatting_risk_for_npm_dependency_reports_medium(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
                "dependencies": {"lodahs": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo-node", "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": True,
                "protected_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_package_age_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("demo==1.0.0\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "pip": {
                    "demo": {
                        "published": "2026-05-20"
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_package_age_checks": True,
                "min_package_age_days": 14,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_filter_guard_path_entries_removes_other_safedeps_paths():
    entries = [
        r"C:\\Python311\\Scripts",
        r"R:\\CodesAndTips\\CodesAndTips\\dotNET\\SafeDeps\\safedeps-Latest\\.safedeps\\bin",
        r"C:\\Tools",
        r"D:\\other\\project\\.safedeps\\bin",
        r"C:\\Python311\\Scripts",
    ]
    keep = r"R:\\CodesAndTips\\CodesAndTips\\dotNET\\SafeDeps\\safedeps-Latest\\.safedeps\\bin"
    filtered = _filter_guard_path_entries(entries, keep)
    assert filtered == [
        r"C:\\Python311\\Scripts",
        r"R:\\CodesAndTips\\CodesAndTips\\dotNET\\SafeDeps\\safedeps-Latest\\.safedeps\\bin",
        r"C:\\Tools",
    ]


def test_strip_autoguard_blocks_removes_multiple_markers():
    text = "\n".join(
        [
            "line-a",
            "# >>> SafeDeps Auto Guard >>>",
            "if (...) { ... }",
            "# <<< SafeDeps Auto Guard <<<",
            "line-b",
            "# >>> SafeDeps Auto Guard >>>",
            "if (...) { ... }",
            "# <<< SafeDeps Auto Guard <<<",
            "line-c",
        ]
    )
    cleaned = _strip_autoguard_blocks(text)
    assert "SafeDeps Auto Guard" not in cleaned
    assert "line-a" in cleaned
    assert "line-b" in cleaned
    assert "line-c" in cleaned


def test_strip_cmd_autorun_blocks_preserves_existing_commands():
    text = (
        'doskey ll=dir & if "SafeDeps Auto Guard"=="SafeDeps Auto Guard" '
        'if exist "C:\\project\\.safedeps\\activate.bat" call "C:\\project\\.safedeps\\activate.bat" & '
        'echo ready'
    )
    cleaned = _strip_cmd_autorun_blocks(text)

    assert "SafeDeps Auto Guard" not in cleaned
    assert ".safedeps" not in cleaned
    assert "doskey ll=dir" in cleaned
    assert "echo ready" in cleaned


def test_strip_cmd_autorun_blocks_removes_legacy_rem_hook():
    text = (
        'doskey ll=dir & rem >>> SafeDeps Auto Guard >>> & '
        'if exist "C:\\project\\.safedeps\\activate.bat" call "C:\\project\\.safedeps\\activate.bat" & '
        'rem <<< SafeDeps Auto Guard <<< & echo ready'
    )
    cleaned = _strip_cmd_autorun_blocks(text)

    assert "SafeDeps Auto Guard" not in cleaned
    assert ".safedeps" not in cleaned
    assert "doskey ll=dir" in cleaned
    assert "echo ready" in cleaned


def test_cleanup_guard_install_disables_auto_guard(monkeypatch, tmp_path):
    (tmp_path / ".safedeps").mkdir()
    guard_mod._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "global", "project_root": str(tmp_path)},
    )

    def fake_set_autoguard(root, enable):
        state = guard_mod._load_guard_state(root)
        state["auto_guard"] = enable
        state["auto_guard_powershell"] = enable
        guard_mod._write_guard_state(root, state)

    monkeypatch.setattr(guard_mod, "_set_user_path_guard_entry", lambda root, enable: True)
    monkeypatch.setattr(guard_mod, "_set_powershell_autoguard", fake_set_autoguard)
    monkeypatch.setattr(guard_mod, "_set_cmd_autorun_autoguard", lambda root, enable: True)

    guard_mod.cleanup_guard_install(tmp_path)

    state = guard_mod._load_guard_state(tmp_path)
    assert state["auto_guard"] is False
    assert state["auto_guard_powershell"] is False


def test_cleanup_guard_install_can_preserve_auto_guard_for_setup(monkeypatch, tmp_path):
    (tmp_path / ".safedeps").mkdir()
    guard_mod._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "global", "project_root": str(tmp_path)},
    )

    def fake_set_autoguard(root, enable):
        state = guard_mod._load_guard_state(root)
        state["auto_guard"] = enable
        state["auto_guard_powershell"] = enable
        guard_mod._write_guard_state(root, state)

    monkeypatch.setattr(guard_mod, "_set_user_path_guard_entry", lambda root, enable: True)
    monkeypatch.setattr(guard_mod, "_set_powershell_autoguard", fake_set_autoguard)
    monkeypatch.setattr(guard_mod, "_set_cmd_autorun_autoguard", lambda root, enable: True)

    guard_mod.cleanup_guard_install(tmp_path, disable_auto_guard=False)

    state = guard_mod._load_guard_state(tmp_path)
    assert state["auto_guard"] is True
    assert state["auto_guard_powershell"] is True


def test_runtime_guard_blocks_direct_python_m_pip_unpinned_install(monkeypatch, tmp_path):
    (tmp_path / ".safedeps").mkdir()
    guard_mod._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "global", "project_root": str(tmp_path)},
    )
    monkeypatch.setattr(sys, "argv", ["-m", "install", "six"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard_mod, "_block", lambda message: (_ for _ in ()).throw(RuntimeError(message)))

    with pytest.raises(RuntimeError, match="unpinned runtime install"):
        runtime_guard_mod.run(str(tmp_path))


def test_runtime_guard_allows_out_of_scope_project_direct_python_m_pip(monkeypatch, tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / ".safedeps").mkdir()
    guard_mod._write_guard_state(
        project,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "project", "project_root": str(project)},
    )
    monkeypatch.setattr(sys, "argv", ["-m", "install", "six"])
    monkeypatch.chdir(outside)

    runtime_guard_mod.run(str(project))


def test_runtime_guard_allows_direct_python_when_auto_guard_off(monkeypatch, tmp_path):
    (tmp_path / ".safedeps").mkdir()
    guard_mod._write_guard_state(
        tmp_path,
        {"auto_guard": False, "auto_guard_powershell": False, "protection_scope": "global", "project_root": str(tmp_path)},
    )
    monkeypatch.setattr(sys, "argv", ["-m", "install", "six"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard_mod, "_block", lambda message: (_ for _ in ()).throw(RuntimeError(message)))

    runtime_guard_mod.run(str(tmp_path))


def test_runtime_guard_pth_line_targets_project_and_interpreter():
    line = guard_mod._runtime_guard_pth_line(Path("C:/demo"), "C:/demo/.venv", "https://github.com/jaydemks/SafeDeps.git")

    assert "safedeps.runtime_guard" in line
    assert "C:/demo" in line
    assert "C:/demo/.venv" in line
    assert "https://github.com/jaydemks/SafeDeps.git" in line


def test_publisher_churn_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"demo-pkg": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "npm": {
                    "demo-pkg": {
                        "publisher_changes_90d": 4
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_publisher_churn_checks": True,
                "max_publisher_changes_90d": 1,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_doctor_fails_without_safedeps_dir(tmp_path):
    code = main(["doctor", str(tmp_path)])
    assert code == 2


def test_doctor_passes_with_valid_policy_and_cache(tmp_path):
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"schema": "safedeps.policy.v1"}), encoding="utf-8")
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(json.dumps({"pip": {"demo": {"published": "2026-05-01"}}}), encoding="utf-8")
    code = main(["doctor", str(tmp_path)])
    assert code == 0


def test_doctor_fails_with_invalid_cache_json(tmp_path):
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"schema": "safedeps.policy.v1"}), encoding="utf-8")
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text("{ invalid", encoding="utf-8")
    code = main(["doctor", str(tmp_path)])
    assert code == 2


def test_maintainer_change_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"demo-pkg": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "npm": {
                    "demo-pkg": {
                        "maintainer_changes_180d": 3
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_maintainer_change_checks": True,
                "max_maintainer_changes_180d": 1,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_scan_writes_sarif_when_requested(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.21"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo-node", "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--sarif", "security-artifacts/safedeps.sarif", "--fail-on", "HIGH"])
    assert code == 0
    sarif_path = tmp_path / "security-artifacts" / "safedeps.sarif"
    assert sarif_path.exists()
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data.get("version") == "2.1.0"
    assert isinstance(data.get("runs"), list) and data["runs"]


def test_scan_writes_cyclonedx_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--cyclonedx", "security-artifacts/safedeps.cdx.json", "--fail-on", "HIGH"])
    assert code == 0
    cdx_path = tmp_path / "security-artifacts" / "safedeps.cdx.json"
    assert cdx_path.exists()
    data = json.loads(cdx_path.read_text(encoding="utf-8"))
    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("specVersion") == "1.5"


def test_scan_writes_spdx_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--spdx", "security-artifacts/safedeps.spdx.json", "--fail-on", "HIGH"])
    assert code == 0
    spdx_path = tmp_path / "security-artifacts" / "safedeps.spdx.json"
    assert spdx_path.exists()
    data = json.loads(spdx_path.read_text(encoding="utf-8"))
    assert data.get("spdxVersion") == "SPDX-2.3"
    assert isinstance(data.get("packages"), list)


def test_sbom_exporters_deduplicate_same_component(tmp_path):
    # Same dependency appears in requirements + requirements.lock; exporters should deduplicate
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main([
        "scan", str(tmp_path),
        "--out", ".tmp-security",
        "--cyclonedx", "security-artifacts/safedeps.cdx.json",
        "--spdx", "security-artifacts/safedeps.spdx.json",
        "--fail-on", "HIGH",
    ])
    assert code == 0

    cdx = json.loads((tmp_path / "security-artifacts" / "safedeps.cdx.json").read_text(encoding="utf-8"))
    spdx = json.loads((tmp_path / "security-artifacts" / "safedeps.spdx.json").read_text(encoding="utf-8"))

    cdx_names = [c.get("name") for c in cdx.get("components", []) if c.get("name") == "requests"]
    spdx_names = [p.get("name") for p in spdx.get("packages", []) if p.get("name") == "requests"]
    assert len(cdx_names) == 1
    assert len(spdx_names) == 1


def test_vulnerability_baseline_suppresses_matching_findings(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"lodash": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
                "enable_vulnerability_baseline": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-baseline.json").write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "manager": "npm",
                        "rule": "FLOATING_VERSION",
                        "package": "lodash",
                        "file": "package.json",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    blocked = [f for f in report.get("findings", []) if f.get("rule") == "FLOATING_VERSION" and f.get("package") == "lodash"]
    assert not blocked


def test_local_vulnerability_feed_adds_normalized_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-feed.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "manager": "pip",
                        "package": "requests",
                        "id": "CVE-2099-0001",
                        "severity": "high",
                        "message": "Test advisory",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    vulns = [f for f in report.get("findings", []) if f.get("rule") == "KNOWN_VULNERABILITY" and f.get("manager") == "pip"]
    assert vulns
    assert vulns[0]["severity"] == "HIGH"


def test_local_osv_feed_adds_vulnerability_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-feed.json").write_text(
        json.dumps(
            {
                "vulnerabilities_osv": [
                    {
                        "id": "OSV-2026-XYZ",
                        "summary": "OSV style advisory",
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "requests"}
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    vulns = [f for f in report.get("findings", []) if f.get("rule") == "KNOWN_VULNERABILITY" and f.get("package") == "requests"]
    assert vulns
    assert vulns[0]["severity"] == "CRITICAL"


def test_vulnerability_baseline_expired_entry_does_not_suppress(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"lodash": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
                "enable_vulnerability_baseline": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-baseline.json").write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "manager": "npm",
                        "rule": "FLOATING_VERSION",
                        "package": "lodash",
                        "file": "package.json",
                        "expires": "2025-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    blocked = [f for f in report.get("findings", []) if f.get("rule") == "FLOATING_VERSION" and f.get("package") == "lodash"]
    assert blocked


def test_baseline_command_generates_suppressions(tmp_path):
    (tmp_path / "security-artifacts").mkdir(parents=True)
    (tmp_path / "security-artifacts" / "safedeps-report.json").write_text(
        json.dumps(
            {
                "ok": False,
                "findings": [
                    {"manager": "npm", "rule": "FLOATING_VERSION", "package": "lodash", "file": "package.json"},
                    {"manager": "pip", "rule": "KNOWN_VULNERABILITY", "package": "requests", "file": "requirements.txt"},
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(["baseline", str(tmp_path)])
    assert code == 0
    baseline = json.loads((tmp_path / ".safedeps" / "vuln-baseline.json").read_text(encoding="utf-8"))
    assert len(baseline.get("suppress", [])) == 2


def test_approve_command_writes_expiring_suppression(tmp_path):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--package",
            "lodash",
            "--file",
            "package.json",
            "--expires",
            "2026-12-31",
        ]
    )
    assert code == 0
    data = json.loads((tmp_path / ".safedeps" / "vuln-baseline.json").read_text(encoding="utf-8"))
    entries = data.get("suppress", [])
    assert len(entries) == 1
    assert entries[0]["expires"] == "2026-12-31"


def test_explain_command_known_rule_ok():
    code = main(["explain", "FLOATING_VERSION"])
    assert code == 0


def test_approve_command_rejects_invalid_date(tmp_path):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--expires",
            "31-12-2026",
        ]
    )
    assert code == 2


def test_scan_writes_html_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    html_rel = "security-artifacts/safedeps-report.html"
    code = main(["scan", str(tmp_path), "--out", "security-artifacts", "--html", html_rel, "--fail-on", "HIGH"])
    assert code == 0
    html_path = tmp_path / html_rel
    assert html_path.exists()
    html_text = html_path.read_text(encoding="utf-8")
    assert "SafeDeps Scan Report" in html_text
    assert "Status:" in html_text


def test_explain_output_stability(capsys):
    code = main(["explain", "FLOATING_VERSION"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "FLOATING_VERSION",
        "Dependency version is not pinned exactly. Pin exact versions to reduce supply-chain drift.",
    ]


def test_explain_unknown_rule_output_stability(capsys):
    code = main(["explain", "UNKNOWN_RULE"])
    assert code == 2
    out = capsys.readouterr().out
    assert "Unknown finding rule: UNKNOWN_RULE" in out
    assert "Tip: run scan and use one of the emitted rule identifiers." in out


def test_doctor_output_stability_without_safedeps_dir(tmp_path, capsys):
    code = main(["doctor", str(tmp_path)])
    assert code == 2
    out = capsys.readouterr().out
    assert "SafeDeps doctor" in out
    assert f"Path: {tmp_path}" in out
    assert "Status: FAIL" in out
    assert "Missing .safedeps directory. Run: safedeps init" in out


def test_baseline_output_stability(tmp_path, capsys):
    (tmp_path / "security-artifacts").mkdir(parents=True)
    (tmp_path / "security-artifacts" / "safedeps-report.json").write_text(
        json.dumps(
            {
                "ok": False,
                "findings": [
                    {"manager": "npm", "rule": "FLOATING_VERSION", "package": "lodash", "file": "package.json"},
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(["baseline", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Baseline written:" in out
    assert "(1 entries)" in out


def test_approve_output_stability(tmp_path, capsys):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--package",
            "lodash",
            "--file",
            "package.json",
            "--expires",
            "2026-12-31",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "Added approval:" in out
    assert "npm/FLOATING_VERSION" in out
    assert "expires=2026-12-31" in out


def test_scan_summary_output_stability_for_clean_project(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", "security-artifacts", "--fail-on", "HIGH"])
    assert code == 0
    out = capsys.readouterr().out
    assert "SafeDeps scan" in out
    assert "Status: PASS   fail-on: HIGH" in out
    assert "Artifacts:" in out


def test_scan_bad_project_fixture_snapshot(capsys):
    code = main(["scan", "examples/bad-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2
    out = capsys.readouterr().out
    # Normalize non-deterministic counts/paths and assert stable key lines.
    normalized_lines = []
    for line in out.splitlines():
        if line.startswith("Findings: "):
            normalized_lines.append("Findings:")
            continue
        if line.startswith("Artifacts: "):
            normalized_lines.append("Artifacts:")
            continue
        if line.startswith("- "):
            match = re.match(r"^- (CRITICAL|HIGH|MEDIUM|LOW|INFO) ([^:]+):", line)
            if match:
                normalized_lines.append(f"- {match.group(1)} {match.group(2)}")
                continue
        normalized_lines.append(line)
    normalized = "\n".join(normalized_lines)

    expected = Path("tests/golden/scan_bad_project_snapshot.txt").read_text(encoding="utf-8")
    for expected_line in expected.splitlines():
        assert expected_line in normalized


def test_setup_generates_strict_project_guard_wrappers(tmp_path):
    code = main(["setup", str(tmp_path)])
    assert code == 0

    state = json.loads((tmp_path / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))
    assert state["auto_guard"] is False
    assert state["project_root"] == str(tmp_path)

    for rel in (".safedeps/bin/pip", ".safedeps/bin/python", ".safedeps/bin/npm", ".safedeps/activate.sh"):
        raw = (tmp_path / rel).read_bytes()
        assert b"\r\n" not in raw

    pip_wrapper = (tmp_path / ".safedeps" / "bin" / "pip").read_text(encoding="utf-8")
    python_wrapper = (tmp_path / ".safedeps" / "bin" / "python").read_text(encoding="utf-8")
    npm_wrapper = (tmp_path / ".safedeps" / "bin" / "npm").read_text(encoding="utf-8")
    pip_ps1 = (tmp_path / ".safedeps" / "bin" / "pip.ps1").read_text(encoding="utf-8")
    python_ps1 = (tmp_path / ".safedeps" / "bin" / "python.ps1").read_text(encoding="utf-8")
    npm_ps1 = (tmp_path / ".safedeps" / "bin" / "npm.ps1").read_text(encoding="utf-8")
    python_cmd = (tmp_path / ".safedeps" / "bin" / "python.cmd").read_text(encoding="utf-8")
    npm_cmd = (tmp_path / ".safedeps" / "bin" / "npm.cmd").read_text(encoding="utf-8")
    pip_cmd = (tmp_path / ".safedeps" / "bin" / "pip.cmd").read_text(encoding="utf-8")
    activate_bat = (tmp_path / ".safedeps" / "activate.bat").read_text(encoding="utf-8")
    assert 'if [ -z "${VIRTUAL_ENV:-}" ]' not in pip_wrapper
    assert 'if [ -z "${VIRTUAL_ENV:-}" ]' not in python_wrapper
    assert "Blocked: pip uninstall is disabled while SafeDeps guard is active." in pip_wrapper
    assert "Blocked: pip uninstall is disabled while SafeDeps guard is active." in pip_ps1
    assert "Blocked: python -m pip uninstall is disabled while SafeDeps guard is active." in python_wrapper
    assert "Blocked: python -m pip uninstall is disabled while SafeDeps guard is active." in python_ps1
    assert "Blocked: python -m pip uninstall is disabled while SafeDeps guard is active." in python_cmd
    assert "setlocal EnableExtensions EnableDelayedExpansion" in pip_cmd
    assert "setlocal EnableExtensions EnableDelayedExpansion" in python_cmd
    assert 'set "_real_python=' in pip_cmd
    assert 'set "_real_python=' in python_cmd
    assert 'call "!_real_python!" -c "import safedeps" >nul 2>nul\nif errorlevel 1 (' in pip_cmd
    assert 'call "!_real_python!" -c "import safedeps" >nul 2>nul\nif errorlevel 1 (' in python_cmd
    assert '("%_real_python%" -c "import safedeps")' not in pip_cmd
    assert '("%_real_python%" -c "import safedeps")' not in python_cmd
    assert "SafeDeps guard wrapper is active, but SafeDeps is not importable" in pip_cmd
    assert "SafeDeps guard wrapper is active, but SafeDeps is not importable" in python_cmd
    assert "[SafeDeps CMD debug] wrapper=pip.cmd" in pip_cmd
    assert "[SafeDeps CMD debug] wrapper=python.cmd" in python_cmd
    assert "get('protection_scope', 'project')" in pip_cmd
    assert "get('protection_scope', 'project')" in python_cmd
    assert 'if ""==""' not in pip_cmd
    assert 'if ""==""' not in python_cmd
    assert '/C:""' not in pip_cmd
    assert '/C:""' not in python_cmd
    assert 'findstr /I /C:"\\"protection_scope\\": \\"global\\""' not in pip_cmd
    assert 'findstr /I /C:"\\"protection_scope\\": \\"global\\""' not in python_cmd
    assert 'if /I not "!_scope!"=="global"' in pip_cmd
    assert 'if /I not "!_scope!"=="global"' in python_cmd
    assert 'if /I "%_scope%"=="global" (\n      "' not in pip_cmd
    assert 'if /I "%_scope%"=="global" (\n        "' not in python_cmd
    assert 'if ($scope -eq "global") {\n      & "' not in pip_ps1
    assert 'and $scope -eq "global") {' not in python_ps1
    assert "normCurVenv = ($curVenv).Replace([char]92, '/')" in pip_ps1
    assert "normCurVenv = ($curVenv).Replace([char]92, '/')" in python_ps1
    assert "normCurVenv = ($curVenv).Replace([char]92, '/')" in npm_ps1
    assert "_expected_venv_norm=!_expected_venv:\\=/!" in pip_cmd
    assert "_expected_venv_norm=!_expected_venv:\\=/!" in python_cmd
    assert "_expected_venv_norm=!_expected_venv:\\=/!" in npm_cmd
    assert 'set "PATH=%safeDepsBin%;%PATH%"' in activate_bat
    assert "SafeDeps pip guard active for this CMD session." in activate_bat
    assert 'REAL_PY="' in npm_wrapper
    assert 'scope="global"' in npm_wrapper


def test_setup_windows_keeps_cmd_bin_free_of_extensionless_wrappers(monkeypatch, tmp_path):
    monkeypatch.setattr(guard_mod, "_is_windows", lambda: True)
    monkeypatch.setattr(guard_mod, "_force_autoguard_resync", lambda root, target_enabled: None)

    stale_bin = tmp_path / ".safedeps" / "bin"
    stale_bin.mkdir(parents=True)
    for name in ("pip", "pip3", "python", "python3", "npm"):
        (stale_bin / name).write_text("stale", encoding="utf-8")

    code = main(["setup", str(tmp_path), "--install-scope", "system"])

    assert code == 0
    state = json.loads((tmp_path / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))
    assert state["protection_scope"] == "global"
    assert (tmp_path / ".safedeps" / "bin" / "pip.cmd").exists()
    assert (tmp_path / ".safedeps" / "bin" / "python.cmd").exists()
    assert (tmp_path / ".safedeps" / "bin-posix" / "pip").exists()
    assert (tmp_path / ".safedeps" / "bin-posix" / "python").exists()
    for name in ("pip", "pip3", "python", "python3", "npm"):
        assert not (tmp_path / ".safedeps" / "bin" / name).exists()


def test_setup_system_can_preserve_project_protection_scope(tmp_path):
    code = main(["setup", str(tmp_path), "--install-scope", "system", "--protection-scope", "project"])

    assert code == 0
    state = json.loads((tmp_path / ".safedeps" / "guard-state.json").read_text(encoding="utf-8"))
    assert state["protection_scope"] == "project"


def test_format_dependency_ui_error_exposes_compatibility_reason():
    raw = "pip uninstall failed: foo\n" \
          "pip uninstall failed compatibility checks and was rolled back. Reason: pip check found missing dependency pytest>=8.0.0"
    out = cli_mod._format_dependency_ui_error(raw)
    assert "Uninstall blocked" in out
    assert "compatibility checks failed" in out
    assert "pip check found missing dependency pytest>=8.0.0" in out


def test_format_dependency_ui_error_compatibility_rollback_reason():
    raw = "pip uninstall failed compatibility checks and rollback also failed. Reason: pip check failed: broken marker"
    out = cli_mod._format_dependency_ui_error(raw)
    assert "Uninstall blocked" in out
    assert "rollback also failed" in out
    assert "pip check failed: broken marker" in out
