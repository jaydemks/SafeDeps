import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import safedeps.runtime_guard as runtime_guard


def test_load_state_returns_empty_for_missing_or_invalid_file(tmp_path):
    assert runtime_guard._load_state(tmp_path) == {}

    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text("[]", encoding="utf-8")

    assert runtime_guard._load_state(tmp_path) == {}


def test_load_state_reads_dict(tmp_path):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(json.dumps({"auto_guard": True}), encoding="utf-8")

    assert runtime_guard._load_state(tmp_path) == {"auto_guard": True}


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["pip", "install", "requests"], "install"),
        (["pip3", "download", "requests"], "download"),
        (["-m", "install", "requests"], "install"),
        (["python", "-m", "pip", "install"], None),
        (["pip"], None),
    ],
)
def test_pip_subcommand(argv, expected):
    assert runtime_guard._pip_subcommand(argv) == expected


def test_package_tokens_skip_options_and_option_values():
    args = [
        "--upgrade",
        "-r",
        "requirements.txt",
        "--index-url",
        "https://internal/simple",
        "requests==2.32.3",
        "--extra-index-url",
        "https://extra/simple",
        "flask",
    ]

    assert runtime_guard._package_tokens(args) == ["requests==2.32.3", "flask"]


def test_package_tokens_skip_equals_style_option_values():
    args = [
        "--index-url=https://internal/simple",
        "--extra-index-url=https://extra/simple",
        "--find-links=./wheelhouse",
        "requests==2.32.3",
    ]

    assert runtime_guard._package_tokens(args) == ["requests==2.32.3"]


def test_requirement_file_tokens_read_requirements_constraints_and_nested_files(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.3\n-r nested.txt\n-c constraints.txt\n",
        encoding="utf-8",
    )
    (tmp_path / "nested.txt").write_text("flask\n", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text("urllib3==2.2.3\n", encoding="utf-8")

    assert runtime_guard._requirement_file_tokens(tmp_path, ["-r", "requirements.txt"]) == [
        "requests==2.32.3",
        "flask",
        "urllib3==2.2.3",
    ]


@pytest.mark.parametrize(
    "token",
    [
        "./dist/pkg.whl",
        "/tmp/pkg.tar.gz",
        r"C:\tmp\pkg.whl",
        "git+https://example/repo.git",
        "demo @ https://example.test/demo-1.0.0.tar.gz",
    ],
)
def test_looks_like_local_or_direct_reference(token):
    assert runtime_guard._looks_like_local_or_direct_reference(token)


def test_contains_safedeps_handles_version_specifiers():
    assert runtime_guard._contains_safedeps(["safedeps==0.3.4"])
    assert runtime_guard._contains_safedeps(["SafeDeps>=0.3"])
    assert runtime_guard._contains_safedeps(["SafeDeps[ui]~=0.4"])
    assert runtime_guard._contains_safedeps(["SafeDeps @ git+https://github.com/jaydemks/SafeDeps.git"])
    assert not runtime_guard._contains_safedeps(["not-safedeps"])


def test_direct_and_local_reference_classification():
    assert runtime_guard._looks_like_local_reference(".")
    assert runtime_guard._looks_like_local_reference("./dist/pkg.whl")
    assert runtime_guard._looks_like_direct_reference("git+https://example/repo.git")
    assert runtime_guard._looks_like_direct_reference("demo @ https://example.test/demo-1.0.0.tar.gz")
    assert not runtime_guard._looks_like_direct_reference("./dist/pkg.whl")


def test_guard_applies_requires_auto_guard_and_project_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/venv")

    assert not runtime_guard._guard_applies(tmp_path, "/venv", {"auto_guard": False})
    assert runtime_guard._guard_applies(
        tmp_path,
        "/venv",
        {"auto_guard": True, "protection_scope": "project", "project_root": str(tmp_path)},
    )
    assert not runtime_guard._guard_applies(
        tmp_path,
        "/other",
        {"auto_guard": True, "protection_scope": "project", "project_root": str(tmp_path)},
    )


def test_guard_applies_global_ignores_cwd_and_expected_venv(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/actual")

    assert runtime_guard._guard_applies(
        tmp_path,
        "/expected",
        {"auto_guard": True, "protection_scope": "global", "project_root": str(tmp_path)},
    )


def test_is_subpath_and_norm_path_handle_normalization(tmp_path):
    child = tmp_path / "project" / "sub"
    child.mkdir(parents=True)

    assert runtime_guard._is_subpath(child, tmp_path / "project")
    assert not runtime_guard._is_subpath(tmp_path, child)
    assert runtime_guard._norm_path(r"C:\Demo\Path\\") == "c:/demo/path"


@pytest.mark.parametrize(
    ("argv", "blocked"),
    [
        (["pip", "install", "requests"], True),
        (["pip", "install", "requests==2.32.3"], False),
        (["pip", "install", "./dist/pkg.whl"], False),
        (["pip", "install", "-e", "."], False),
        (["pip", "install", "safedeps==0.4.0"], True),
    ],
)
def test_run_blocks_unpinned_install_only_when_guard_applies(tmp_path, monkeypatch, argv, blocked):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps({"auto_guard": True, "protection_scope": "project", "project_root": str(tmp_path)}),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/venv")
    monkeypatch.setattr(runtime_guard.sys, "argv", argv)
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", lambda fail_on="HIGH": None)
    messages = []
    exits = []
    monkeypatch.setattr(runtime_guard.sys, "stderr", SimpleNamespace(write=messages.append, flush=lambda: None))
    monkeypatch.setattr(runtime_guard.os, "_exit", lambda code: exits.append(code))

    runtime_guard.run(str(tmp_path), expected_venv="/venv")

    if blocked:
        assert exits == [2]
        assert "unpinned runtime install" in "".join(messages) or "official Git source" in "".join(messages)
    else:
        assert exits == []


def test_run_blocks_unpinned_install_from_requirement_file(tmp_path, monkeypatch):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps({"auto_guard": True, "protection_scope": "project", "project_root": str(tmp_path)}),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/venv")
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "install", "-r", "requirements.txt"])
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", lambda fail_on="HIGH": None)
    monkeypatch.setattr(runtime_guard, "_block", lambda message: (_ for _ in ()).throw(RuntimeError(message)))

    with pytest.raises(RuntimeError, match="unpinned runtime install"):
        runtime_guard.run(str(tmp_path), expected_venv="/venv")


def test_run_blocks_direct_url_runtime_install(tmp_path, monkeypatch):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps({"auto_guard": True, "protection_scope": "project", "project_root": str(tmp_path)}),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/venv")
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "install", "demo @ git+https://example.test/demo.git"])
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", lambda fail_on="HIGH": None)
    monkeypatch.setattr(runtime_guard, "_block", lambda message: (_ for _ in ()).throw(RuntimeError(message)))

    with pytest.raises(RuntimeError, match="direct URL/VCS runtime install"):
        runtime_guard.run(str(tmp_path), expected_venv="/venv")


def test_run_respects_bypass_non_guarded_commands_and_inactive_guard(tmp_path, monkeypatch):
    monkeypatch.setattr(
        runtime_guard,
        "_run_scan_or_block",
        lambda fail_on="HIGH": (_ for _ in ()).throw(AssertionError("scan")),
    )
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "list"])

    runtime_guard.run(str(tmp_path))

    monkeypatch.setenv("SAFEDEPS_RUNTIME_GUARD_BYPASS", "1")
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "install", "requests"])
    runtime_guard.run(str(tmp_path))

    monkeypatch.delenv("SAFEDEPS_RUNTIME_GUARD_BYPASS")
    (tmp_path / ".safedeps").mkdir(exist_ok=True)
    (tmp_path / ".safedeps" / "guard-state.json").write_text(json.dumps({"auto_guard": False}), encoding="utf-8")
    runtime_guard.run(str(tmp_path))


def test_run_blocks_uninstall_except_safedeps_self_uninstall(tmp_path, monkeypatch):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps({"auto_guard": True, "protection_scope": "global", "project_root": str(tmp_path)}),
        encoding="utf-8",
    )
    exits = []
    messages = []
    cleanup_calls = []
    monkeypatch.setattr(runtime_guard.sys, "stderr", SimpleNamespace(write=messages.append, flush=lambda: None))
    monkeypatch.setattr(runtime_guard.os, "_exit", lambda code: exits.append(code))
    monkeypatch.setattr(runtime_guard, "_cleanup_before_self_uninstall", lambda root: cleanup_calls.append(root))
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", lambda fail_on="HIGH": None)

    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "uninstall", "requests"])
    runtime_guard.run(str(tmp_path))
    assert exits == [2]
    assert "pip uninstall is disabled" in "".join(messages)

    exits.clear()
    messages.clear()
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "uninstall", "safedeps"])
    runtime_guard.run(str(tmp_path))
    assert exits == []
    assert cleanup_calls == [tmp_path.resolve()]


def test_run_blocks_safedeps_update_unless_official_repo_matches(tmp_path, monkeypatch):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps({"auto_guard": True, "protection_scope": "global", "project_root": str(tmp_path)}),
        encoding="utf-8",
    )
    exits = []
    messages = []
    monkeypatch.setattr(runtime_guard.sys, "stderr", SimpleNamespace(write=messages.append, flush=lambda: None))
    monkeypatch.setattr(runtime_guard.os, "_exit", lambda code: exits.append(code))
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", lambda fail_on="HIGH": None)

    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "download", "safedeps==0.4.0"])
    runtime_guard.run(str(tmp_path), official_repo="https://github.com/jaydemks/SafeDeps")
    assert exits == [2]
    assert "official Git source" in "".join(messages)

    exits.clear()
    messages.clear()
    monkeypatch.setattr(
        runtime_guard.sys,
        "argv",
        ["pip", "download", "SafeDeps @ git+HTTPS://github.com/jaydemks/SafeDeps.git"],
    )
    runtime_guard.run(str(tmp_path), official_repo="https://github.com/jaydemks/SafeDeps")
    assert exits == []


def test_run_scan_or_block_preserves_argv_and_blocks_on_nonzero(monkeypatch):
    calls = []
    messages = []
    exits = []

    def fake_main(args):
        calls.append(args)
        runtime_guard.sys.argv.append("mutated")
        return 2

    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "install"])
    monkeypatch.setattr(runtime_guard.sys, "stderr", SimpleNamespace(write=messages.append, flush=lambda: None))
    monkeypatch.setattr(runtime_guard.os, "_exit", lambda code: exits.append(code))
    monkeypatch.setitem(__import__("sys").modules, "safedeps.cli", SimpleNamespace(main=fake_main))

    runtime_guard._run_scan_or_block("HIGH")

    assert calls == [["scan", ".", "--fail-on", "HIGH"]]
    assert runtime_guard.sys.argv == ["pip", "install"]
    assert exits == [2]
    assert "blocked pip" in "".join(messages)


def test_run_passes_saved_fail_on_threshold_to_scan(tmp_path, monkeypatch):
    state_file = tmp_path / ".safedeps" / "guard-state.json"
    state_file.parent.mkdir()
    state_file.write_text(
        json.dumps(
            {
                "auto_guard": True,
                "protection_scope": "project",
                "project_root": str(tmp_path),
                "fail_on": "MEDIUM",
            }
        ),
        encoding="utf-8",
    )
    calls = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runtime_guard.sys, "prefix", "/venv")
    monkeypatch.setattr(runtime_guard.sys, "argv", ["pip", "install", "requests==2.32.3"])
    monkeypatch.setattr(runtime_guard, "_run_scan_or_block", calls.append)

    runtime_guard.run(str(tmp_path), expected_venv="/venv")

    assert calls == ["MEDIUM"]
