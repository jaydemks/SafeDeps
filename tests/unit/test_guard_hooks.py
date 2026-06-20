from pathlib import Path

import safedeps.guard_hooks as guard_hooks


def test_init_project_writes_policy_once(tmp_path):
    guard_hooks._init_project(tmp_path, force=False)
    policy = tmp_path / ".safedeps" / "policy.json"
    original = policy.read_text(encoding="utf-8")

    policy.write_text('{"custom": true}', encoding="utf-8")
    guard_hooks._init_project(tmp_path, force=False)

    assert policy.read_text(encoding="utf-8") == '{"custom": true}'

    guard_hooks._init_project(tmp_path, force=True)
    assert policy.read_text(encoding="utf-8") == original


def test_runtime_guard_pth_helpers_escape_inputs(tmp_path):
    line = guard_hooks._runtime_guard_pth_line(
        tmp_path,
        expected_venv="C:/venv",
        official_repo="https://example/repo.git",
    )

    assert line.startswith("import sys; exec(")
    assert "safedeps.runtime_guard" in line
    assert str(tmp_path) in line
    assert guard_hooks._runtime_guard_pth_name() in guard_hooks._runtime_guard_pth_names()


def test_site_package_candidates_are_deduplicated_and_sorted(monkeypatch, tmp_path):
    site_packages = tmp_path / "lib" / "site-packages"
    user_site = tmp_path / "user-site"

    monkeypatch.setattr(guard_hooks.site, "getsitepackages", lambda: [str(user_site), str(site_packages), str(site_packages)])
    monkeypatch.setattr(guard_hooks.site, "getusersitepackages", lambda: str(user_site))

    assert guard_hooks._site_package_candidates() == [site_packages, user_site]


def test_site_package_candidates_tolerates_site_api_failures(monkeypatch):
    monkeypatch.setattr(
        guard_hooks.site,
        "getsitepackages",
        lambda: (_ for _ in ()).throw(RuntimeError("no global site")),
    )
    monkeypatch.setattr(
        guard_hooks.site,
        "getusersitepackages",
        lambda: (_ for _ in ()).throw(RuntimeError("no user site")),
    )

    assert guard_hooks._site_package_candidates() == []


def test_install_interpreter_guard_hook_is_disabled_under_pytest(monkeypatch, tmp_path):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")

    assert guard_hooks.install_interpreter_guard_hook(tmp_path, "", "") is None


def test_install_interpreter_guard_hook_writes_first_available_site_dir(monkeypatch, tmp_path):
    blocked = tmp_path / "blocked"
    writable = tmp_path / "site-packages"
    calls = []

    class BlockedDir:
        def mkdir(self, *args, **kwargs):
            calls.append("blocked")
            raise OSError("read-only")

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(guard_hooks, "_site_package_candidates", lambda: [BlockedDir(), writable])

    installed = guard_hooks.install_interpreter_guard_hook(
        tmp_path,
        expected_venv="/venv",
        official_repo="https://example/repo.git",
    )

    assert calls == ["blocked"]
    assert installed == writable / guard_hooks._runtime_guard_pth_name()
    text = installed.read_text(encoding="utf-8")
    assert "safedeps.runtime_guard" in text
    assert "https://example/repo.git" in text


def test_remove_interpreter_guard_hook_removes_old_and_new_names(monkeypatch, tmp_path):
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    paths = []
    for name in guard_hooks._runtime_guard_pth_names():
        target = site_dir / name
        target.write_text("x", encoding="utf-8")
        paths.append(target)
    monkeypatch.setattr(guard_hooks, "_site_package_candidates", lambda: [site_dir])

    removed = guard_hooks.remove_interpreter_guard_hook()

    assert removed == paths
    assert not any(path.exists() for path in paths)
