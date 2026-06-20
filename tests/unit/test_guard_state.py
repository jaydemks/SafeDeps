import json
import os
import sys
from types import SimpleNamespace

import pytest

import safedeps.guard_state as guard_state


def test_setup_status_reports_missing_and_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(guard_state, "_is_windows", lambda: False)

    missing_status = guard_state.get_setup_status(tmp_path)
    assert "Not configured" in missing_status
    assert "policy" in missing_status

    safedeps_dir = tmp_path / ".safedeps"
    (safedeps_dir / "bin").mkdir(parents=True)
    for rel in ("policy.json", "activate.sh", "activate.bat", "activate.ps1"):
        (safedeps_dir / rel).write_text("x", encoding="utf-8")
    (safedeps_dir / "bin" / "pip").write_text("x", encoding="utf-8")

    assert guard_state.get_setup_status(tmp_path).startswith("Configured.")


def test_filter_guard_path_entries_deduplicates_and_keeps_requested_guard_bin():
    entries = [
        "/usr/bin",
        "/project/.safedeps/bin",
        "/usr/bin",
        "/other/.safedeps/bin",
        "/project/.safedeps/bin",
    ]

    assert guard_state._filter_guard_path_entries(entries, "/project/.safedeps/bin") == [
        "/usr/bin",
        "/project/.safedeps/bin",
    ]
    assert guard_state._filter_guard_path_entries(entries, None) == ["/usr/bin"]


def test_strip_autoguard_blocks_removes_only_safedeps_section():
    text = "before\n# >>> SafeDeps Auto Guard >>>\nremove me\n# <<< SafeDeps Auto Guard <<<\nafter\n"

    assert guard_state._strip_autoguard_blocks(text) == "before\nafter\n"


def test_strip_cmd_autorun_blocks_removes_old_and_new_snippets():
    old = 'first & rem >>> SafeDeps Auto Guard >>> call x rem <<< SafeDeps Auto Guard <<< & last'
    new = 'first & if "SafeDeps Auto Guard"=="SafeDeps Auto Guard" if exist "C:\\p\\.safedeps\\activate.bat" call "C:\\p\\.safedeps\\activate.bat" & last'

    assert guard_state._strip_cmd_autorun_blocks(old) == "first & last"
    assert guard_state._strip_cmd_autorun_blocks(new) == "first & last"


def test_load_guard_state_handles_legacy_auto_guard_keys(tmp_path):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(json.dumps({"auto_guard_powershell": True}), encoding="utf-8")

    state = guard_state._load_guard_state(tmp_path)

    assert state["auto_guard"]
    assert state["auto_guard_powershell"]
    assert state["protection_scope"] == "project"


def test_load_guard_state_handles_missing_corrupt_and_non_dict_files(tmp_path):
    default = guard_state._load_guard_state(tmp_path)
    assert default["auto_guard"] is False
    assert default["project_root"] == str(tmp_path)

    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text("[1, 2, 3]", encoding="utf-8")
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is False

    state_file.write_text("{", encoding="utf-8")
    assert guard_state._load_guard_state(tmp_path)["auto_guard_powershell"] is False

    state_file.write_text(json.dumps({"auto_guard": True}), encoding="utf-8")
    state = guard_state._load_guard_state(tmp_path)
    assert state["auto_guard"] is True
    assert state["auto_guard_powershell"] is True


def test_project_install_scope_uses_explicit_scope_or_virtualenv(monkeypatch):
    assert guard_state._is_project_install_scope("venv") is True
    assert guard_state._is_project_install_scope("global") is False

    monkeypatch.setattr(guard_state.sys, "prefix", "/venv")
    monkeypatch.setattr(guard_state.sys, "base_prefix", "/base")
    assert guard_state._running_in_virtualenv_for_safedeps() is True
    assert guard_state._is_project_install_scope(None) is True


def test_apply_guard_toggle_updates_scope_and_rejects_unknown_action(tmp_path):
    assert "PROJECT ONLY" in guard_state.apply_guard_toggle(tmp_path, "set_scope_project")
    assert guard_state.get_protection_scope(tmp_path) == "project"

    assert "forced to PROJECT" in guard_state.apply_guard_toggle(tmp_path, "set_scope_global", install_scope="project")
    assert guard_state.get_protection_scope(tmp_path) == "project"

    assert "GLOBAL" in guard_state.apply_guard_toggle(tmp_path, "set_scope_global", install_scope="system")
    assert guard_state.get_protection_scope(tmp_path) == "global"

    with pytest.raises(ValueError, match="Unknown guard action"):
        guard_state.apply_guard_toggle(tmp_path, "bad")


def test_apply_guard_toggle_delegates_enable_disable(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        guard_state,
        "_set_powershell_autoguard",
        lambda root, enable: calls.append((root, enable)) or f"set:{enable}",
    )

    assert guard_state.apply_guard_toggle(tmp_path, "enable_auto") == "set:True"
    assert guard_state.apply_guard_toggle(tmp_path, "disable_auto") == "set:False"
    assert calls == [(tmp_path, True), (tmp_path, False)]


def test_set_user_path_guard_entry_updates_current_process_path(tmp_path, monkeypatch):
    monkeypatch.setattr(guard_state, "_is_windows", lambda: False)
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", str(tmp_path / ".safedeps" / "bin")]))

    assert guard_state._set_user_path_guard_entry(tmp_path, True)
    entries = os.environ["PATH"].split(os.pathsep)
    guard_bin = str((tmp_path / ".safedeps" / "bin").resolve())
    assert guard_bin in entries
    assert entries.count(guard_bin) <= 1

    assert guard_state._set_user_path_guard_entry(tmp_path, False)
    assert ".safedeps" not in os.environ["PATH"]


def test_set_user_path_guard_entry_updates_windows_registry_and_env(tmp_path, monkeypatch):
    writes = []
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)
    monkeypatch.setattr(guard_state, "_get_user_path_entries_windows", lambda: ["C:/Tools", "C:/old/.safedeps/bin"])
    monkeypatch.setattr(guard_state, "_write_user_path_entries_windows", lambda entries: writes.append(entries) or True)
    monkeypatch.setenv("PATH", os.pathsep.join(["/usr/bin", "/old/.safedeps/bin"]))

    assert guard_state._set_user_path_guard_entry(tmp_path, True) is True

    guard_bin = str((tmp_path / ".safedeps" / "bin").resolve())
    assert writes[-1][0] == guard_bin
    assert "C:/old/.safedeps/bin" not in writes[-1]
    assert os.environ["PATH"].split(os.pathsep)[0] == guard_bin

    assert guard_state._set_user_path_guard_entry(tmp_path, False) is True
    assert all(".safedeps" not in entry for entry in writes[-1])


def test_current_shell_guard_status_reads_path(tmp_path, monkeypatch):
    bindir = str((tmp_path / ".safedeps" / "bin").resolve())
    monkeypatch.setenv("PATH", bindir)

    assert "ACTIVE" in guard_state.get_current_shell_guard_status(tmp_path)

    monkeypatch.setenv("PATH", "/usr/bin")
    assert "INACTIVE" in guard_state.get_current_shell_guard_status(tmp_path)


def test_windows_registry_helpers_read_write_and_delete(monkeypatch):
    class FakeKey:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    values = {"Path": "C:/Tools;C:/Bin", "AutoRun": "echo hi"}

    fake_winreg = SimpleNamespace(
        HKEY_CURRENT_USER=object(),
        KEY_READ=1,
        KEY_SET_VALUE=2,
        REG_EXPAND_SZ=3,
        OpenKey=lambda *args: FakeKey(),
        CreateKeyEx=lambda *args: FakeKey(),
        QueryValueEx=lambda key, name: (values[name], None),
        SetValueEx=lambda key, name, reserved, kind, value: values.__setitem__(name, value),
        DeleteValue=lambda key, name: values.pop(name),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)

    assert guard_state._get_user_path_entries_windows() == ["C:/Tools", "C:/Bin"]
    assert guard_state._write_user_path_entries_windows(["C:/One", "C:/Two"]) is True
    assert values["Path"] == "C:/One;C:/Two"
    assert guard_state._get_cmd_autorun_windows() == "echo hi"
    assert guard_state._write_cmd_autorun_windows("echo next") is True
    assert values["AutoRun"] == "echo next"
    assert guard_state._write_cmd_autorun_windows("") is True
    assert "AutoRun" not in values


def test_windows_registry_helpers_return_defaults_on_errors(monkeypatch):
    fake_winreg = SimpleNamespace(
        HKEY_CURRENT_USER=object(),
        KEY_READ=1,
        KEY_SET_VALUE=2,
        OpenKey=lambda *args: (_ for _ in ()).throw(OSError("registry unavailable")),
        CreateKeyEx=lambda *args: (_ for _ in ()).throw(OSError("registry unavailable")),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg)
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)

    assert guard_state._get_user_path_entries_windows() == []
    assert guard_state._write_user_path_entries_windows(["C:/Tools"]) is False
    assert guard_state._get_cmd_autorun_windows() == ""
    assert guard_state._write_cmd_autorun_windows("echo hi") is False


def test_powershell_autoguard_enable_disable_updates_profiles_and_state(tmp_path, monkeypatch):
    profiles = [
        tmp_path / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
        tmp_path / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
    ]
    monkeypatch.setattr(guard_state, "_powershell_profile_candidates", lambda: profiles)
    monkeypatch.setattr(guard_state, "_is_windows", lambda: False)
    monkeypatch.setenv("PATH", "/usr/bin")

    enabled = guard_state._set_powershell_autoguard(tmp_path, True)

    assert "enabled" in enabled
    for profile in profiles:
        text = profile.read_text(encoding="utf-8")
        assert "SafeDeps Auto Guard" in text
        assert str((tmp_path / ".safedeps" / "activate.ps1").resolve()) in text
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is True
    assert str((tmp_path / ".safedeps" / "bin").resolve()) in os.environ["PATH"]
    assert guard_state._profile_snippet_present(tmp_path) is True
    assert guard_state._verify_autoguard_state(tmp_path, True) is True

    disabled = guard_state._set_powershell_autoguard(tmp_path, False)

    assert "disabled" in disabled
    assert all("SafeDeps Auto Guard" not in p.read_text(encoding="utf-8") for p in profiles)
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is False
    assert ".safedeps" not in os.environ["PATH"]


def test_powershell_autoguard_skips_write_failures_and_reports_already_disabled(tmp_path, monkeypatch):
    class FailingProfile:
        parent = tmp_path

        def exists(self):
            return True

        def read_text(self, encoding):
            return "# >>> SafeDeps Auto Guard >>>\nold\n# <<< SafeDeps Auto Guard <<<\n"

        def write_text(self, text, encoding):
            raise OSError("cannot write")

    monkeypatch.setattr(guard_state, "_powershell_profile_candidates", lambda: [FailingProfile()])
    monkeypatch.setattr(guard_state, "_set_user_path_guard_entry", lambda root, enable: True)
    monkeypatch.setattr(guard_state, "_set_cmd_autorun_autoguard", lambda root, enable: False)

    message = guard_state._set_powershell_autoguard(tmp_path, False)

    assert "already disabled" in message
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is False


def test_powershell_autoguard_skips_unwritable_profiles_but_updates_state(tmp_path, monkeypatch):
    class BlockedParent:
        def mkdir(self, *args, **kwargs):
            raise OSError("read-only")

    class BlockedProfile:
        parent = BlockedParent()

        def exists(self):
            return False

    profile = BlockedProfile()
    calls = []
    monkeypatch.setattr(guard_state, "_powershell_profile_candidates", lambda: [profile])
    monkeypatch.setattr(guard_state, "_set_user_path_guard_entry", lambda root, enable: calls.append(("path", enable)) or True)
    monkeypatch.setattr(guard_state, "_set_cmd_autorun_autoguard", lambda root, enable: calls.append(("cmd", enable)) or False)

    message = guard_state._set_powershell_autoguard(tmp_path, True)

    assert "already enabled" in message
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is True
    assert ("path", True) in calls


def test_profile_snippet_present_ignores_missing_unreadable_and_wrong_snippets(tmp_path, monkeypatch):
    class MissingProfile:
        def exists(self):
            return False

    class UnreadableProfile:
        def exists(self):
            return True

        def read_text(self, encoding):
            raise OSError("cannot read")

    wrong_profile = tmp_path / "wrong.ps1"
    wrong_profile.write_text("# >>> SafeDeps Auto Guard >>>\nwrong\n# <<< SafeDeps Auto Guard <<<\n", encoding="utf-8")
    right_profile = tmp_path / "right.ps1"
    right_profile.write_text(guard_state._guard_profile_snippet(tmp_path), encoding="utf-8")
    monkeypatch.setattr(
        guard_state,
        "_powershell_profile_candidates",
        lambda: [MissingProfile(), UnreadableProfile(), wrong_profile],
    )

    assert guard_state._profile_snippet_present(tmp_path) is False

    monkeypatch.setattr(guard_state, "_powershell_profile_candidates", lambda: [right_profile])
    assert guard_state._profile_snippet_present(tmp_path) is True


def test_sync_autoguard_state_file_tracks_effective_path_state(tmp_path, monkeypatch):
    monkeypatch.setattr(guard_state, "_is_windows", lambda: False)
    bindir = str((tmp_path / ".safedeps" / "bin").resolve())

    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": False, "auto_guard_powershell": False, "protection_scope": "project"},
    )
    monkeypatch.setenv("PATH", bindir)

    assert guard_state._sync_autoguard_state_file(tmp_path) is True
    state = guard_state._load_guard_state(tmp_path)
    assert state["auto_guard"] is True
    assert state["auto_guard_powershell"] is True

    monkeypatch.setenv("PATH", "/usr/bin")
    assert guard_state._sync_autoguard_state_file(tmp_path) is False
    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is False


def test_sync_autoguard_state_file_leaves_matching_state_untouched(tmp_path, monkeypatch):
    writes = []
    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "project"},
    )
    monkeypatch.setattr(guard_state, "_effective_autoguard_enabled", lambda root: True)
    monkeypatch.setattr(guard_state, "_write_guard_state", lambda root, state: writes.append(state))

    assert guard_state._sync_autoguard_state_file(tmp_path) is True
    assert writes == []


def test_verify_autoguard_state_checks_negative_and_partial_positive(tmp_path, monkeypatch):
    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "project"},
    )
    monkeypatch.setattr(guard_state, "_profile_snippet_present", lambda root: False)
    monkeypatch.setattr(guard_state, "_cmd_autorun_snippet_present", lambda root: False)
    monkeypatch.setattr(guard_state, "_path_guard_entry_present", lambda root: False)

    assert guard_state._verify_autoguard_state(tmp_path, True) is False

    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": False, "auto_guard_powershell": False, "protection_scope": "project"},
    )
    assert guard_state._verify_autoguard_state(tmp_path, False) is True


def test_path_guard_entry_present_normalizes_windows_backslashes(tmp_path, monkeypatch):
    guard_bin = str((tmp_path / ".safedeps" / "bin").resolve()).replace("/", "\\")
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)
    monkeypatch.setattr(guard_state, "_get_user_path_entries_windows", lambda: [guard_bin])

    assert guard_state._path_guard_entry_present(tmp_path)


def test_cmd_autorun_autoguard_updates_windows_autorun(tmp_path, monkeypatch):
    values = {"autorun": "echo before"}
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)
    monkeypatch.setattr(guard_state, "_get_cmd_autorun_windows", lambda: values["autorun"])
    monkeypatch.setattr(guard_state, "_write_cmd_autorun_windows", lambda value: values.update(autorun=value) or True)

    assert guard_state._set_cmd_autorun_autoguard(tmp_path, True) is True
    assert "echo before" in values["autorun"]
    assert "SafeDeps Auto Guard" in values["autorun"]
    assert guard_state._cmd_autorun_snippet_present(tmp_path) is True

    assert guard_state._set_cmd_autorun_autoguard(tmp_path, False) is True
    assert values["autorun"] == "echo before"
    assert guard_state._cmd_autorun_snippet_present(tmp_path) is False


def test_cmd_autorun_autoguard_noops_when_snippet_already_matches(tmp_path, monkeypatch):
    snippet = guard_state._cmd_autorun_snippet(tmp_path)
    monkeypatch.setattr(guard_state, "_is_windows", lambda: True)
    monkeypatch.setattr(guard_state, "_get_cmd_autorun_windows", lambda: snippet)
    monkeypatch.setattr(
        guard_state,
        "_write_cmd_autorun_windows",
        lambda value: (_ for _ in ()).throw(AssertionError("should not write")),
    )

    assert guard_state._set_cmd_autorun_autoguard(tmp_path, True) is False


def test_cleanup_guard_install_disables_autoguard_and_removes_project_artifacts(tmp_path, monkeypatch):
    calls = []
    bindir = tmp_path / ".safedeps" / "bin"
    posix_bindir = tmp_path / ".safedeps" / "bin-posix"
    bindir.mkdir(parents=True)
    posix_bindir.mkdir(parents=True)
    for rel in ("activate.sh", "activate.bat", "activate.ps1"):
        (tmp_path / ".safedeps" / rel).write_text("activate", encoding="utf-8")
    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "global"},
    )
    monkeypatch.setenv("pip", "wrapped")
    monkeypatch.setenv("npm", "wrapped")
    monkeypatch.setattr(guard_state, "_set_user_path_guard_entry", lambda root, enable: calls.append(("path", enable)) or True)
    monkeypatch.setattr(guard_state, "_set_powershell_autoguard", lambda root, enable: calls.append(("ps", enable)) or "ok")
    monkeypatch.setattr(guard_state, "_set_cmd_autorun_autoguard", lambda root, enable: calls.append(("cmd", enable)) or True)
    monkeypatch.setattr(guard_state, "remove_interpreter_guard_hook", lambda: calls.append(("hook", None)))

    assert guard_state.cleanup_guard_install(tmp_path, remove_project_artifacts=True) == 0

    assert guard_state._load_guard_state(tmp_path)["auto_guard"] is False
    assert not bindir.exists()
    assert not posix_bindir.exists()
    assert not (tmp_path / ".safedeps" / "activate.sh").exists()
    assert "pip" not in os.environ
    assert "npm" not in os.environ
    assert ("path", False) in calls
    assert ("ps", False) in calls
    assert ("cmd", False) in calls
    assert ("hook", None) in calls


def test_cleanup_guard_install_can_preserve_auto_guard_and_ignores_unlink_errors(tmp_path, monkeypatch):
    calls = []
    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": True, "auto_guard_powershell": True, "protection_scope": "global"},
    )

    class ProblemPath:
        def exists(self):
            return True

        def unlink(self):
            raise OSError("locked")

    original_truediv = guard_state.Path.__truediv__

    def fake_truediv(self, other):
        if str(other) == ".safedeps/activate.ps1":
            return ProblemPath()
        return original_truediv(self, other)

    monkeypatch.setattr(guard_state.Path, "__truediv__", fake_truediv)
    monkeypatch.setattr(guard_state, "_set_user_path_guard_entry", lambda root, enable: calls.append(("path", enable)) or True)
    monkeypatch.setattr(guard_state, "_set_powershell_autoguard", lambda root, enable: calls.append(("ps", enable)) or "ok")
    monkeypatch.setattr(guard_state, "_set_cmd_autorun_autoguard", lambda root, enable: calls.append(("cmd", enable)) or True)
    monkeypatch.setattr(guard_state, "remove_interpreter_guard_hook", lambda: calls.append(("hook", None)))

    assert guard_state.cleanup_guard_install(
        tmp_path,
        remove_project_artifacts=True,
        disable_auto_guard=False,
    ) == 0

    state = guard_state._load_guard_state(tmp_path)
    assert state["auto_guard"] is True
    assert state["auto_guard_powershell"] is True
    assert calls.count(("ps", False)) == 1


def test_force_autoguard_resync_retries_until_target_state(tmp_path, monkeypatch):
    calls = []
    verify_results = iter([False, False, False, False])

    def fake_verify(root, expected_enabled):
        calls.append(("verify", expected_enabled))
        return next(verify_results)

    monkeypatch.setattr(guard_state, "_set_powershell_autoguard", lambda root, enable: calls.append(("set", enable)))
    monkeypatch.setattr(guard_state, "_verify_autoguard_state", fake_verify)

    guard_state._force_autoguard_resync(tmp_path, True)
    guard_state._force_autoguard_resync(tmp_path, False)

    assert calls == [
        ("set", False),
        ("verify", False),
        ("set", False),
        ("set", True),
        ("verify", True),
        ("set", True),
        ("set", True),
        ("verify", True),
        ("set", True),
        ("set", False),
        ("verify", False),
        ("set", False),
    ]


@pytest.mark.parametrize(
    ("enabled", "path_active", "expected"),
    [
        (True, True, "ON now + auto-start ON"),
        (False, True, "ON in this session"),
        (True, False, "Auto-start ON"),
        (False, False, "OFF now"),
    ],
)
def test_get_guard_mode_status_reports_session_and_autostart(tmp_path, monkeypatch, enabled, path_active, expected):
    monkeypatch.setattr(guard_state, "_is_auto_guard_enabled", lambda root: enabled)
    monkeypatch.setattr(
        guard_state,
        "get_current_shell_guard_status",
        lambda root: "ACTIVE" if path_active else "wrapper path missing",
    )
    guard_state._write_guard_state(
        tmp_path,
        {"auto_guard": enabled, "auto_guard_powershell": enabled, "protection_scope": "global"},
    )

    assert expected in guard_state.get_guard_mode_status(tmp_path)
