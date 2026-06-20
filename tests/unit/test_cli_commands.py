from types import SimpleNamespace

import safedeps.cli as cli


def test_cmd_init_writes_policy_and_respects_existing_file(tmp_path, capsys):
    args = SimpleNamespace(path=str(tmp_path), force=False)

    assert cli.cmd_init(args) == 0
    policy = tmp_path / ".safedeps" / "policy.json"
    assert policy.exists()
    assert "SafeDeps policy written" in capsys.readouterr().out

    policy.write_text('{"custom": true}', encoding="utf-8")
    assert cli.cmd_init(args) == 0
    assert policy.read_text(encoding="utf-8") == '{"custom": true}'

    args.force = True
    assert cli.cmd_init(args) == 0
    assert "allowed_registries" in policy.read_text(encoding="utf-8")


def test_cmd_help_prints_operational_quickstart(capsys):
    assert cli.cmd_help(SimpleNamespace()) == 0

    out = capsys.readouterr().out
    assert "SafeDeps Quick Help" in out
    assert "safedeps scan" in out
    assert "pip install colorama==0.4.6" in out


def test_cmd_guard_cleanup_delegates_and_swallows_cleanup_errors(monkeypatch, tmp_path):
    calls = []

    def fake_cleanup(root, remove_project_artifacts, disable_auto_guard):
        calls.append((root, remove_project_artifacts, disable_auto_guard))

    monkeypatch.setattr(cli._guard, "cleanup_guard_install", fake_cleanup)

    assert cli.cmd_guard_cleanup(
        SimpleNamespace(path=str(tmp_path), remove_project_artifacts=True)
    ) == 0
    assert calls == [(tmp_path.resolve(), True, True)]

    monkeypatch.setattr(
        cli._guard,
        "cleanup_guard_install",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert cli.cmd_guard_cleanup(SimpleNamespace(path=str(tmp_path))) == 0


def test_guard_facades_delegate_to_guard_module(monkeypatch, tmp_path):
    monkeypatch.setattr(cli._guard, "get_setup_status", lambda root: {"root": str(root)})
    monkeypatch.setattr(cli._guard, "_guard_state_file", lambda root: root / ".safedeps" / "state.json")
    monkeypatch.setattr(cli._guard, "_powershell_profile_candidates", lambda: ["profile.ps1"])
    monkeypatch.setattr(cli._guard, "_guard_profile_snippet", lambda root: f"snippet:{root.name}")
    monkeypatch.setattr(cli._guard, "_load_guard_state", lambda root: {"loaded": True})
    monkeypatch.setattr(cli._guard, "_write_guard_state", lambda root, state: {"written": state})
    monkeypatch.setattr(cli._guard, "_is_auto_guard_enabled", lambda root: True)
    monkeypatch.setattr(cli._guard, "_set_powershell_autoguard", lambda root, enable: f"auto:{enable}")
    monkeypatch.setattr(cli._guard, "apply_guard_toggle", lambda root, action, install_scope=None: f"{action}:{install_scope}")
    monkeypatch.setattr(cli._guard, "get_guard_mode_status", lambda root: {"mode": "project"})
    monkeypatch.setattr(cli._guard, "get_protection_scope", lambda root: "project")
    monkeypatch.setattr(cli._guard, "detect_official_repo_url", lambda root: "https://example.test/repo")
    monkeypatch.setattr(cli._guard, "get_current_shell_guard_status", lambda root: {"active": True})

    assert cli.get_setup_status(tmp_path) == {"root": str(tmp_path)}
    assert cli._guard_state_file(tmp_path).name == "state.json"
    assert cli._powershell_profile_candidates() == ["profile.ps1"]
    assert cli._guard_profile_snippet(tmp_path) == f"snippet:{tmp_path.name}"
    assert cli._load_guard_state(tmp_path) == {"loaded": True}
    assert cli._write_guard_state(tmp_path, {"x": 1}) == {"written": {"x": 1}}
    assert cli._is_auto_guard_enabled(tmp_path) is True
    assert cli._set_powershell_autoguard(tmp_path, False) == "auto:False"
    assert cli.apply_guard_toggle(tmp_path, "enable", install_scope="project") == "enable:project"
    assert cli.get_guard_mode_status(tmp_path) == {"mode": "project"}
    assert cli.get_protection_scope(tmp_path) == "project"
    assert cli.detect_official_repo_url(tmp_path) == "https://example.test/repo"
    assert cli.get_current_shell_guard_status(tmp_path) == {"active": True}


def test_apply_dependency_action_facade_wires_cli_overrides(monkeypatch, tmp_path):
    captured = {}

    def fake_apply_dependency_action(**kwargs):
        captured.update(kwargs)
        assert cli._dependency_actions_mod.run_scan_pipeline is cli.run_scan_pipeline
        assert cli._dependency_actions_mod._run_cmd is cli._run_cmd
        assert cli._dependency_actions_mod._runtime_python_for_action is cli._runtime_python_for_action
        assert cli._dependency_actions_mod._runtime_python_for_system_scope is cli._runtime_python_for_system_scope
        return "ok", "logs"

    monkeypatch.setattr(cli._dependency_actions_mod, "apply_dependency_action", fake_apply_dependency_action)

    assert cli.apply_dependency_action(
        tmp_path,
        "pip",
        "install",
        "requests",
        "1.0.0",
        "manual",
        True,
        "reviewed",
        action_scope="project",
    ) == ("ok", "logs")
    assert captured["root"] == tmp_path
    assert captured["manager"] == "pip"
    assert captured["action_scope"] == "project"
