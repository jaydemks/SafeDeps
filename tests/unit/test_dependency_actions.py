import importlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import safedeps.dependency_actions as dependency_actions
from safedeps.models import ScanResult


def test_policy_quick_update_adds_registry_and_deny_entries(tmp_path):
    msg = dependency_actions.apply_policy_quick_update(
        tmp_path, "add_registry", "pip", "", "https://internal/simple", ""
    )
    assert "Added registry" in msg

    msg = dependency_actions.apply_policy_quick_update(tmp_path, "add_deny", "", "danger", "", "")
    assert "Added deny package" in msg

    msg = dependency_actions.apply_policy_quick_update(tmp_path, "remove_deny", "", "DANGER", "", "")
    assert "Removed deny package" in msg


def test_policy_quick_update_handles_duplicates_custom_paths_and_errors(tmp_path):
    custom_policy = tmp_path / "config" / "policy.json"
    msg = dependency_actions.apply_policy_quick_update(
        tmp_path,
        "add_registry",
        "npm",
        "",
        "https://registry.npmjs.org",
        "config/policy.json",
    )
    assert "Added registry" in msg
    assert custom_policy.exists()

    msg = dependency_actions.apply_policy_quick_update(
        tmp_path,
        "add_registry",
        "npm",
        "",
        "https://registry.npmjs.org",
        str(custom_policy),
    )
    assert "Registry already present" in msg

    msg = dependency_actions.apply_policy_quick_update(tmp_path, "add_deny", "", "danger", "", str(custom_policy))
    assert "Added deny package" in msg
    assert "already in denylist" in dependency_actions.apply_policy_quick_update(
        tmp_path,
        "add_deny",
        "",
        "danger",
        "",
        str(custom_policy),
    )
    assert "not found in denylist" in dependency_actions.apply_policy_quick_update(
        tmp_path,
        "remove_deny",
        "",
        "missing",
        "",
        str(custom_policy),
    )

    with pytest.raises(ValueError, match="manager is required"):
        dependency_actions.apply_policy_quick_update(tmp_path, "add_registry", "", "", "https://repo", "")
    with pytest.raises(ValueError, match="registry URL is required"):
        dependency_actions.apply_policy_quick_update(tmp_path, "add_registry", "pip", "", "", "")
    with pytest.raises(ValueError, match="package is required"):
        dependency_actions.apply_policy_quick_update(tmp_path, "add_deny", "", "", "", "")
    with pytest.raises(ValueError, match="Unknown policy action"):
        dependency_actions.apply_policy_quick_update(tmp_path, "unknown", "", "", "", "")

    broken_policy = tmp_path / "broken.json"
    broken_policy.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid policy JSON"):
        dependency_actions.apply_policy_quick_update(tmp_path, "add_deny", "", "pkg", "", str(broken_policy))


@pytest.mark.parametrize(
    ("name", "expected"),
    [("requests", True), ("@scope/pkg", True), ("bad name", False), ("bad!", False), ("", False)],
)
def test_is_valid_package_name(name, expected):
    assert dependency_actions._is_valid_package_name(name) is expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [("1.2.3", True), ("latest", False), (">=1", False), ("^1.2.3", False), ("1.x", False), ("", False)],
)
def test_is_exact_version(version, expected):
    assert dependency_actions._is_exact_version(version) is expected


def test_format_helpers_make_command_output_and_user_errors():
    assert dependency_actions._format_command_output(["pip", "show", "requests"], 0, "").endswith("(exit code: 0)")
    assert "exact version" in dependency_actions._format_dependency_ui_error(
        "Manual install/update requires an exact version"
    )
    assert "compatibility checks failed" in dependency_actions._format_dependency_ui_error(
        "pip update failed compatibility checks and was rolled back. Reason: pip check failed"
    )


def test_format_dependency_ui_error_covers_blockers_and_uninstall_labels():
    assert dependency_actions._format_dependency_ui_error("Uninstall blocked: package required") == (
        "Uninstall blocked: package required"
    )
    assert "approval checkbox" in dependency_actions._format_dependency_ui_error(
        "Explicit approval required before this dependency change. Risk notes: metadata missing."
    )
    assert "CRITICAL findings" in dependency_actions._format_dependency_ui_error("Blocked by CRITICAL findings.")
    assert "Uninstall blocked" in dependency_actions._format_dependency_ui_error(
        "pip uninstall failed compatibility checks and was rolled back."
    )
    assert "rollback also failed" in dependency_actions._format_dependency_ui_error(
        "npm update failed compatibility checks and rollback also failed."
    )
    assert dependency_actions._format_dependency_ui_error("raw failure") == "raw failure"


def test_run_cmd_returns_stdout_or_stderr(monkeypatch, tmp_path):
    module = importlib.reload(dependency_actions)

    def fake_run(args, cwd, capture_output, text):
        if args[-1] == "stdout":
            return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
        return SimpleNamespace(returncode=3, stdout="", stderr="err\n")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    code, text = module._run_cmd(["cmd", "stdout"], tmp_path)
    assert (code, text) == (0, "ok")

    code, text = module._run_cmd(["cmd", "stderr"], tmp_path)
    assert (code, text) == (3, "err")


def test_safe_auto_version_pip_parses_first_available_version(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "_run_cmd",
        lambda args, cwd: (0, "pkg (2.0)\nAvailable versions: 2.0, 1.0"),
    )

    assert dependency_actions._safe_auto_version_pip(tmp_path, "pkg", runtime_python="python") == "2.0"


def test_safe_auto_version_pip_reports_resolution_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (1, "network down"))
    with pytest.raises(ValueError, match="pip index versions failed"):
        dependency_actions._safe_auto_version_pip(tmp_path, "pkg", runtime_python="python")

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "no version line"))
    with pytest.raises(ValueError, match="Could not resolve available versions"):
        dependency_actions._safe_auto_version_pip(tmp_path, "pkg", runtime_python="python")

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "Available versions: "))
    with pytest.raises(ValueError, match="No versions returned"):
        dependency_actions._safe_auto_version_pip(tmp_path, "pkg", runtime_python="python")


def test_safe_auto_version_npm_parses_json_string(monkeypatch, tmp_path):
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, '"1.2.3"'))

    assert dependency_actions._safe_auto_version_npm(tmp_path, "pkg") == "1.2.3"


def test_safe_auto_version_npm_accepts_plain_text_and_rejects_bad_payloads(monkeypatch, tmp_path):
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "1.2.3"))
    assert dependency_actions._safe_auto_version_npm(tmp_path, "pkg") == "1.2.3"

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (1, "not found"))
    with pytest.raises(ValueError, match="npm view failed"):
        dependency_actions._safe_auto_version_npm(tmp_path, "pkg")

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, '["1.0.0"]'))
    with pytest.raises(ValueError, match="Could not resolve latest npm version"):
        dependency_actions._safe_auto_version_npm(tmp_path, "pkg")


def test_get_installed_version_pip_and_required_by(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "_run_cmd",
        lambda args, cwd: (0, "Name: requests\nVersion: 2.32.3\nRequired-by: flask, demo\n"),
    )

    assert dependency_actions._get_installed_version(tmp_path, "pip", "requests", "python") == "2.32.3"
    assert dependency_actions._get_pip_required_by(tmp_path, "requests", "python") == ["demo", "flask"]


def test_get_installed_version_handles_missing_pip_npm_and_unknown_manager(monkeypatch, tmp_path):
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (1, "missing"))
    assert dependency_actions._get_installed_version(tmp_path, "pip", "requests", "python") == ""
    assert dependency_actions._get_pip_required_by(tmp_path, "requests", "python") == []

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "Name: requests\n"))
    assert dependency_actions._get_installed_version(tmp_path, "pip", "requests", "python") == ""
    assert dependency_actions._get_pip_required_by(tmp_path, "requests", "python") == []

    monkeypatch.setattr(
        dependency_actions,
        "_run_cmd",
        lambda args, cwd: (0, '{"dependencies":{"left-pad":{"version":"1.3.0"}}}'),
    )
    assert dependency_actions._get_installed_version(tmp_path, "npm", "left-pad") == "1.3.0"

    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "not json"))
    assert dependency_actions._get_installed_version(tmp_path, "npm", "left-pad") == ""
    assert dependency_actions._get_installed_version(tmp_path, "gem", "rails") == ""


def test_post_change_checks_reports_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (1, "broken"))

    assert dependency_actions._post_change_compat_checks(tmp_path, "pip", "python") == [
        "pip check failed: broken"
    ]


def test_post_change_checks_handles_npm_and_unknown_manager(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, cwd):
        calls.append(args)
        return 0, "ok"

    monkeypatch.setattr(dependency_actions, "_run_cmd", fake_run)
    assert dependency_actions._post_change_compat_checks(tmp_path, "npm") == []
    assert calls == [["npm", "ls", "--depth=0"]]
    assert dependency_actions._post_change_compat_checks(tmp_path, "gem") == []


def test_rollback_dependency_change_uses_install_or_uninstall(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, cwd):
        calls.append(args)
        return 0, "ok"

    monkeypatch.setattr(dependency_actions, "_run_cmd", fake_run)

    assert dependency_actions._rollback_dependency_change(tmp_path, "pip", "requests", "2.0", "python") == (True, "ok")
    assert calls[-1] == ["python", "-m", "pip", "install", "requests==2.0"]

    assert dependency_actions._rollback_dependency_change(tmp_path, "pip", "requests", "", "python") == (True, "ok")
    assert calls[-1] == ["python", "-m", "pip", "uninstall", "-y", "requests"]


def test_rollback_dependency_change_handles_npm_and_unknown_manager(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, cwd):
        calls.append(args)
        return (0, "ok") if args[1] != "uninstall" else (1, "failed")

    monkeypatch.setattr(dependency_actions, "_run_cmd", fake_run)

    assert dependency_actions._rollback_dependency_change(tmp_path, "npm", "left-pad", "1.0.0") == (True, "ok")
    assert calls[-1] == ["npm", "install", "left-pad@1.0.0"]
    assert dependency_actions._rollback_dependency_change(tmp_path, "npm", "left-pad", "") == (False, "failed")
    assert calls[-1] == ["npm", "uninstall", "left-pad"]
    assert dependency_actions._rollback_dependency_change(tmp_path, "gem", "rails", "") == (
        False,
        "Unsupported manager for rollback.",
    )


def test_evaluate_dependency_risk_flags_missing_recent_invalid_and_unresolved_metadata(tmp_path):
    assert dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "requests", "1.0.0", "manual") == [
        "No trusted package metadata found in local intelligence cache."
    ]

    cache = tmp_path / ".safedeps" / "metadata-cache.json"
    cache.parent.mkdir()
    today = datetime.now(timezone.utc).date()
    cache.write_text(
        json.dumps(
            {
                "pip": {
                    "newpkg": {"published": today.isoformat()},
                    "recentpkg": {"published": (today - timedelta(days=4)).isoformat()},
                    "badpkg": {"published": "not-a-date"},
                    "emptypkg": {"published": ""},
                }
            }
        ),
        encoding="utf-8",
    )

    assert "very new" in dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "newpkg", "1.0.0", "manual")[0]
    assert "recent" in dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "recentpkg", "1.0.0", "manual")[0]
    assert "invalid/unreadable" in dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "badpkg", "1.0.0", "manual")[0]
    assert dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "emptypkg", "", "auto") == [
        "No trusted package metadata found in local intelligence cache.",
        "Auto mode could not determine a pinned version.",
    ]


def test_evaluate_dependency_risk_blocks_denylisted_package(tmp_path):
    policy_file = tmp_path / ".safedeps" / "policy.json"
    policy_file.parent.mkdir()
    policy_file.write_text(json.dumps({"deny_packages": ["evil"]}), encoding="utf-8")

    with pytest.raises(ValueError, match="denylisted"):
        dependency_actions._evaluate_dependency_risk(tmp_path, "pip", "evil", "1.0.0", "manual")


@pytest.mark.parametrize(
    ("manager", "action", "package", "message"),
    [
        ("gem", "install", "requests", "Manager must be pip or npm"),
        ("pip", "downgrade", "requests", "Action must be install"),
        ("pip", "install", "bad name", "Invalid package name"),
    ],
)
def test_apply_dependency_action_rejects_invalid_inputs(tmp_path, manager, action, package, message):
    with pytest.raises(ValueError, match=message):
        dependency_actions.apply_dependency_action(
            tmp_path,
            manager,
            action,
            package,
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_blocks_on_pre_scan_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(False, [], {}), tmp_path / "security-artifacts"),
    )

    with pytest.raises(ValueError, match="Blocked by CRITICAL"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "install",
            "requests",
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_requires_exact_manual_version(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")

    with pytest.raises(ValueError, match="exact version"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "install",
            "requests",
            ">=1.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_requires_approval_for_risk_warnings(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: ["metadata missing"])

    with pytest.raises(ValueError, match="Explicit approval required"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "install",
            "requests",
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_successful_pip_install(monkeypatch, tmp_path):
    scans = []
    commands = []

    def fake_scan(**kwargs):
        scans.append(kwargs)
        return ScanResult(True, [], {}), tmp_path / "security-artifacts"

    def fake_run(args, cwd):
        commands.append(args)
        return 0, "installed"

    monkeypatch.setattr(dependency_actions, "run_scan_pipeline", fake_scan)
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "")
    monkeypatch.setattr(dependency_actions, "_post_change_compat_checks", lambda *args, **kwargs: [])
    monkeypatch.setattr(dependency_actions, "_run_cmd", fake_run)

    message, logs = dependency_actions.apply_dependency_action(
        tmp_path,
        "pip",
        "install",
        "requests",
        "1.0.0",
        "manual",
        True,
        "reviewed",
    )

    assert "pip install completed" in message
    assert "Explicit approval confirmed" in message
    assert commands == [["python", "-m", "pip", "install", "requests==1.0.0"]]
    assert len(scans) == 2
    assert "post-change guard checks passed" in logs


def test_apply_dependency_action_blocks_pip_uninstall_when_required_by(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "1.0.0")
    monkeypatch.setattr(dependency_actions, "_get_pip_required_by", lambda *args, **kwargs: ["flask"])

    with pytest.raises(ValueError, match="Uninstall blocked"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "uninstall",
            "requests",
            "",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_rolls_back_after_compat_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "0.9.0")
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "installed"))
    monkeypatch.setattr(dependency_actions, "_post_change_compat_checks", lambda *args, **kwargs: ["pip check failed"])
    monkeypatch.setattr(dependency_actions, "_rollback_dependency_change", lambda *args, **kwargs: (True, "restored"))

    with pytest.raises(ValueError, match="was rolled back"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "update",
            "requests",
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_npm_auto_success(monkeypatch, tmp_path):
    commands = []

    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_safe_auto_version_npm", lambda root, package: "2.0.0")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "1.0.0")
    monkeypatch.setattr(dependency_actions, "_post_change_compat_checks", lambda *args, **kwargs: [])

    def fake_run(args, cwd):
        commands.append(args)
        return 0, "changed"

    monkeypatch.setattr(dependency_actions, "_run_cmd", fake_run)

    message, logs = dependency_actions.apply_dependency_action(
        tmp_path,
        "npm",
        "update",
        "left-pad",
        "",
        "auto",
        False,
        "",
    )

    assert "npm update completed for left-pad @2.0.0" in message
    assert ["npm", "install", "left-pad@2.0.0"] in commands
    assert "$ npm ls left-pad --depth=0 --json" in logs


def test_apply_dependency_action_reports_command_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "")
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (2, "permission denied"))

    with pytest.raises(ValueError, match="pip install failed"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "install",
            "requests",
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_reports_scope_miss_for_uninstall(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "")
    monkeypatch.setattr(dependency_actions, "_get_pip_required_by", lambda *args, **kwargs: [])
    monkeypatch.setattr(dependency_actions, "get_protection_scope", lambda root: "global")
    monkeypatch.setattr(
        dependency_actions,
        "_run_cmd",
        lambda args, cwd: (0, "WARNING: Skipping requests as it is not installed."),
    )

    with pytest.raises(ValueError, match="selected global runtime scope"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "uninstall",
            "requests",
            "",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_reports_rollback_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "")
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "installed"))
    monkeypatch.setattr(dependency_actions, "_post_change_compat_checks", lambda *args, **kwargs: ["npm ls failed"])
    monkeypatch.setattr(dependency_actions, "_rollback_dependency_change", lambda *args, **kwargs: (False, "rollback denied"))

    with pytest.raises(ValueError, match="rollback also failed"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "npm",
            "install",
            "left-pad",
            "1.0.0",
            "manual",
            False,
            "",
        )


def test_apply_dependency_action_reports_post_scan_critical(monkeypatch, tmp_path):
    scans = [ScanResult(True, [], {}), ScanResult(False, [], {})]

    monkeypatch.setattr(
        dependency_actions,
        "run_scan_pipeline",
        lambda **kwargs: (scans.pop(0), tmp_path / "security-artifacts"),
    )
    monkeypatch.setattr(dependency_actions, "_runtime_python_for_action", lambda root, action_scope=None: "python")
    monkeypatch.setattr(dependency_actions, "_evaluate_dependency_risk", lambda *args: [])
    monkeypatch.setattr(dependency_actions, "_get_installed_version", lambda *args, **kwargs: "")
    monkeypatch.setattr(dependency_actions, "_post_change_compat_checks", lambda *args, **kwargs: [])
    monkeypatch.setattr(dependency_actions, "_run_cmd", lambda args, cwd: (0, "installed"))

    with pytest.raises(ValueError, match="post-check found CRITICAL"):
        dependency_actions.apply_dependency_action(
            tmp_path,
            "pip",
            "install",
            "requests",
            "1.0.0",
            "manual",
            False,
            "",
        )
