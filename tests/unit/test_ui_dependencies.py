from types import SimpleNamespace

import pytest

import safedeps.cli as cli
import safedeps.ui_dependencies as ui_dependencies
from safedeps.models import Finding, ScanResult


@pytest.fixture(autouse=True)
def restore_runtime_collector(monkeypatch):
    monkeypatch.setattr(ui_dependencies, "collect_runtime_components", cli._ORIGINAL_COLLECT_RUNTIME_COMPONENTS)


def test_render_findings_table_handles_empty_and_escapes_action_values():
    assert ui_dependencies.render_findings_table(ScanResult(True, [], {})) == "<p>No findings.</p>"

    result = ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="HIGH",
                manager="pip",
                rule="BAD'RULE",
                package="pkg<script>",
                file="requirements.txt",
                message="Use < 1.0",
            )
        ],
        sbom={},
    )

    html = ui_dependencies.render_findings_table(result)

    assert "&lt;script&gt;" in html
    assert "BAD\\'RULE" in html
    assert "Use For Approval" in html


def test_render_dependency_rows_table_merges_findings_and_empty_components():
    assert "No dependencies detected" in ui_dependencies._render_dependency_rows_table(
        ScanResult(True, [], {}),
        "HIGH",
        [],
    )

    result = ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="CRITICAL",
                manager="pip",
                rule="MALICIOUS_PACKAGE",
                package="demo",
                file="requirements.txt",
                message="bad",
            ),
            Finding(
                severity="LOW",
                manager="npm",
                rule="KNOWN_ISSUE",
                package="missing-declared",
                file="package.json",
                message="warn",
            ),
        ],
        sbom={
            "components": [
                {"type": "library", "manager": "", "name": "ignored", "version": "0", "scope": "dependencies"},
                {"type": "library", "manager": "pip", "name": "demo", "version": "1.0.0", "scope": "dependencies"},
                {"type": "library", "manager": "pip", "name": "demo", "version": "1.0.1", "scope": "runtime:project:pip"},
            ]
        },
    )

    html = ui_dependencies._render_dependency_rows_table(result, "HIGH", result.sbom["components"])

    assert "demo" in html
    assert "1.0.0" in html
    assert "1.0.1" in html
    assert "Blocked" in html
    assert "missing-declared" in html
    assert "Approve (+30 days)" in html


def test_render_dependency_table_handles_empty_project_scope_and_project_install(monkeypatch, tmp_path):
    monkeypatch.setattr(ui_dependencies, "collect_runtime_components", lambda *args, **kwargs: [])

    empty = ScanResult(True, [], {"components": []})
    assert "No dependencies detected in the current scan" in ui_dependencies.render_dependency_table(
        empty,
        "HIGH",
        tmp_path,
        "project",
        installation_scope="project",
    )

    result = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "pip", "name": "declared", "version": "1.0.0", "scope": "dependencies"},
                {"type": "library", "manager": "pip", "name": "system-only", "version": "2.0.0", "scope": "runtime:system:pip"},
            ]
        },
    )

    html = ui_dependencies.render_dependency_table(
        result,
        "HIGH",
        tmp_path,
        "project",
        installation_scope="project",
    )

    assert "Project dependencies" in html
    assert "declared" in html
    assert "system-only" not in html

    runtime_only = ScanResult(
        ok=True,
        findings=[],
        sbom={
            "components": [
                {"type": "library", "manager": "pip", "name": "system-only", "version": "2.0.0", "scope": "runtime:system:pip"},
            ]
        },
    )
    runtime_only_html = ui_dependencies.render_dependency_table(
        runtime_only,
        "HIGH",
        tmp_path,
        "project",
        installation_scope="project",
    )
    assert "Project dependencies" in runtime_only_html
    assert "No dependencies detected for this scope" in runtime_only_html


def test_render_dependency_table_system_scope_collects_runtime_sections(monkeypatch, tmp_path):
    monkeypatch.setattr(ui_dependencies, "_has_project_runtime_candidates", lambda root: True)

    def fake_collect(root, **kwargs):
        scope = kwargs["runtime_scope"]
        if scope == "runtime:system":
            return [
                {"type": "library", "manager": "pip", "name": "system-runtime", "version": "3.0.0", "scope": "runtime:system:pip"}
            ]
        if scope == "runtime:project":
            return [
                {"type": "library", "manager": "pip", "name": "project-runtime", "version": "2.0.0", "scope": "runtime:project:pip"}
            ]
        return []

    class Mode:
        label = "system"
        is_system_install = True
        is_project_install = False

        def system_runtime_python(self):
            return "system-python"

        def project_runtime_python(self):
            return "project-python"

    monkeypatch.setattr(ui_dependencies, "_install_mode", lambda root, label=None: Mode())
    monkeypatch.setattr(ui_dependencies, "collect_runtime_components", fake_collect)

    html = ui_dependencies.render_dependency_table(
        ScanResult(True, [], {"components": []}),
        "HIGH",
        tmp_path,
        "project",
        installation_scope="system",
    )

    assert "Project runtime dependencies" in html
    assert "System/runtime dependencies" in html
    assert "project-runtime" in html
    assert "system-runtime" in html


def test_render_dependency_table_returns_scope_empty_when_only_invalid_runtime(monkeypatch, tmp_path):
    class Mode:
        label = "system"
        is_system_install = True
        is_project_install = False

        def system_runtime_python(self):
            return "system-python"

        def project_runtime_python(self):
            return None

    monkeypatch.setattr(ui_dependencies, "_install_mode", lambda root, label=None: Mode())
    monkeypatch.setattr(
        ui_dependencies,
        "collect_runtime_components",
        lambda *args, **kwargs: [{"type": "library", "manager": "", "name": "", "version": "", "scope": "runtime:system:pip"}],
    )

    html = ui_dependencies.render_dependency_table(
        ScanResult(True, [], {"components": []}),
        "HIGH",
        tmp_path,
        "global",
        installation_scope="system",
    )

    assert "No dependencies detected for this scope" in html


def test_collect_runtime_components_uses_pip_list_importlib_fallback_and_npm(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:3] == ["python", "-m", "pip"]:
            return SimpleNamespace(returncode=0, stdout='[{"name":"pip-pkg","version":"1.2.3"}, "bad"]')
        if args[:2] == ["npm", "ls"]:
            return SimpleNamespace(returncode=0, stdout='{"dependencies":{"left-pad":{"version":"1.3.0"},"empty":{}}}')
        raise AssertionError(args)

    monkeypatch.setattr(ui_dependencies.subprocess, "run", fake_run)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    components = ui_dependencies.collect_runtime_components(
        tmp_path,
        python_executable="python",
        runtime_scope="runtime:system",
        local_only=True,
    )

    assert {"manager": "pip", "name": "pip-pkg", "version": "1.2.3", "scope": "runtime:system:pip", "type": "library"} in components
    assert {"manager": "npm", "name": "left-pad", "version": "1.3.0", "scope": "runtime:system:npm", "type": "library"} in components
    assert any(call[-1] == "--local" for call in calls)

    def fallback_run(args, **kwargs):
        if args[:3] == ["python", "-m", "pip"]:
            return SimpleNamespace(returncode=1, stdout="")
        if args[:2] == ["python", "-c"]:
            return SimpleNamespace(returncode=0, stdout='[{"name":"meta-pkg","version":"4.5.6"},{}]')
        if args[:2] == ["npm", "ls"]:
            raise RuntimeError("npm unavailable")
        raise AssertionError(args)

    monkeypatch.setattr(ui_dependencies.subprocess, "run", fallback_run)
    components = ui_dependencies.collect_runtime_components(
        tmp_path,
        python_executable="python",
        runtime_scope=":",
    )

    assert components == [
        {"type": "library", "manager": "pip", "name": "meta-pkg", "version": "4.5.6", "scope": "runtime:pip"}
    ]


def test_collect_runtime_components_ignores_bad_runtime_payloads(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:3] == ["python", "-m", "pip"]:
            raise RuntimeError("pip unavailable")
        if args[:2] == ["python", "-c"]:
            return SimpleNamespace(returncode=0, stdout='"not a list"')
        if args[:2] == ["npm", "ls"]:
            return SimpleNamespace(returncode=0, stdout='{"dependencies":["bad"]}')
        raise AssertionError(args)

    monkeypatch.setattr(ui_dependencies.subprocess, "run", fake_run)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    assert ui_dependencies.collect_runtime_components(
        tmp_path,
        python_executable="python",
        runtime_scope="runtime:",
    ) == []
    assert any(call[:2] == ["npm", "ls"] for call in calls)


def test_collect_runtime_components_without_runtime_returns_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(ui_dependencies, "_detect_project_runtime_python", lambda root: None)

    assert ui_dependencies.collect_runtime_components(
        tmp_path,
        python_executable=None,
        fallback_to_process=False,
    ) == []


def test_render_pip_guard_panel_reports_clear_and_blocked_states():
    clear = ScanResult(
        ok=True,
        findings=[Finding(severity="HIGH", manager="npm", rule="NPM", package="pkg", message="blocked")],
        sbom={},
    )
    assert "no blocking pip findings" in ui_dependencies.render_pip_guard_panel(clear, "HIGH")

    blocked = ScanResult(
        ok=False,
        findings=[
            Finding(severity="INFO", manager="pip", rule="INFO_RULE", package="info", message="ignored"),
            Finding(severity="CRITICAL", manager="pip", rule="BAD", package="", message="<blocked>"),
        ],
        sbom={},
    )
    html = ui_dependencies.render_pip_guard_panel(blocked, "HIGH")

    assert "1 blocking finding" in html
    assert "(unknown)" in html
    assert "&lt;blocked&gt;" in html
