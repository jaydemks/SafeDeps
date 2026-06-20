from io import BytesIO
from types import SimpleNamespace

import pytest

import safedeps.ui_server as ui_server
from safedeps.models import ScanResult


class FakeInstallMode:
    label = "project"
    is_system_install = False

    def enforce_project_state(self, path):
        return None

    def can_set_guard_action(self, action):
        return True, ""

    def action_scope(self, requested_scope, protection_scope):
        return requested_scope or protection_scope


def _capture_handler(monkeypatch, tmp_path, install_mode=None):
    captured = {}

    class FakeServer:
        def __init__(self, address, handler_cls):
            captured["handler_cls"] = handler_cls

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            return None

    monkeypatch.setattr(ui_server, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(ui_server, "_resolve_ui_start_path", lambda raw: tmp_path)
    monkeypatch.setattr(ui_server, "_install_mode", lambda root, label=None: install_mode or FakeInstallMode())
    monkeypatch.setattr(
        ui_server,
        "render_ui_page",
        lambda path, fail_on, **kwargs: (
            f"path={path}; fail_on={fail_on}; "
            f"notice={kwargs.get('notice', '')}; error={kwargs.get('error', '')}; "
            f"dependency_output={kwargs.get('ui_state', {}).get('dependency_output', '')}"
        ),
    )

    ui_server.cmd_ui(
        SimpleNamespace(
            host="127.0.0.1",
            port=5200,
            path=str(tmp_path),
            fail_on="HIGH",
            install_scope="auto",
            open_browser=False,
        )
    )
    return captured["handler_cls"]


def _make_handler(handler_cls, path, body=""):
    handler = object.__new__(handler_cls)
    handler.path = path
    handler.headers = {"Content-Length": str(len(body.encode("utf-8")))}
    handler.rfile = BytesIO(body.encode("utf-8"))
    handler.wfile = BytesIO()
    handler.responses = []
    handler.errors = []
    handler.headers_sent = []
    handler.send_response = lambda code: handler.responses.append(code)
    handler.send_header = lambda key, value: handler.headers_sent.append((key, value))
    handler.end_headers = lambda: None
    handler.send_error = lambda code: handler.errors.append(code)
    return handler


def test_cmd_ui_shortcut_is_windows_only(monkeypatch, capsys):
    monkeypatch.setattr(ui_server.os, "name", "posix")

    assert ui_server.cmd_ui_shortcut(SimpleNamespace()) == 2
    assert "Windows only" in capsys.readouterr().out


def test_cmd_ui_shortcut_writes_windows_launcher(monkeypatch, tmp_path, capsys):
    host_path_cls = type(tmp_path)
    workspace = tmp_path / "workspace"
    userprofile = tmp_path / "profile"
    monkeypatch.setattr(ui_server.os, "name", "nt")
    monkeypatch.setattr(ui_server, "Path", host_path_cls)
    monkeypatch.setenv("USERPROFILE", str(userprofile))
    monkeypatch.setattr(ui_server, "_default_ui_workspace", lambda: workspace)

    assert ui_server.cmd_ui_shortcut(SimpleNamespace()) == 0

    launcher = userprofile / "Desktop" / "SafeDeps UI.bat"
    assert launcher.exists()
    content = launcher.read_text(encoding="utf-8")
    assert f'cd /d "{workspace}"' in content
    assert "safedeps ui . --host 127.0.0.1 --port 5200 --open-browser" in content
    assert "Desktop launcher created" in capsys.readouterr().out


def test_cmd_ui_starts_server_without_opening_browser(monkeypatch, tmp_path, capsys):
    events = []

    class FakeServer:
        def __init__(self, address, handler_cls):
            events.append(("init", address, handler_cls.__name__))

        def serve_forever(self):
            events.append(("serve",))
            raise KeyboardInterrupt

        def server_close(self):
            events.append(("close",))

    monkeypatch.setattr(ui_server, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(ui_server, "_resolve_ui_start_path", lambda raw: tmp_path)

    code = ui_server.cmd_ui(
        SimpleNamespace(
            host="127.0.0.1",
            port=5200,
            path=str(tmp_path),
            fail_on="HIGH",
            install_scope="auto",
            open_browser=False,
        )
    )

    assert code == 0
    assert events[0][:2] == ("init", ("127.0.0.1", 5200))
    assert ("serve",) in events
    assert ("close",) in events
    assert "SafeDeps UI running at http://127.0.0.1:5200/" in capsys.readouterr().out


def test_cmd_ui_falls_back_to_next_available_port(monkeypatch, tmp_path, capsys):
    attempts = []

    class FakeServer:
        def __init__(self, address, handler_cls):
            attempts.append(address)
            if address[1] == 5200:
                raise OSError("busy")

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            return None

    monkeypatch.setattr(ui_server, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(ui_server, "_resolve_ui_start_path", lambda raw: tmp_path)

    assert ui_server.cmd_ui(
        SimpleNamespace(
            host="127.0.0.1",
            port=5200,
            path=str(tmp_path),
            fail_on="HIGH",
            install_scope="auto",
            open_browser=False,
        )
    ) == 0

    out = capsys.readouterr().out
    assert attempts[:2] == [("127.0.0.1", 5200), ("127.0.0.1", 5201)]
    assert "port 5200 not available" in out
    assert "http://127.0.0.1:5201/" in out


def test_cmd_ui_raises_when_all_ports_are_busy(monkeypatch, tmp_path):
    class BusyServer:
        def __init__(self, address, handler_cls):
            raise OSError("busy")

    monkeypatch.setattr(ui_server, "ThreadingHTTPServer", BusyServer)
    monkeypatch.setattr(ui_server, "_resolve_ui_start_path", lambda raw: tmp_path)

    with pytest.raises(OSError, match="busy"):
        ui_server.cmd_ui(
            SimpleNamespace(
                host="127.0.0.1",
                port=5200,
                path=str(tmp_path),
                fail_on="HIGH",
                install_scope="auto",
                open_browser=False,
            )
        )


def test_ui_handler_get_root_asset_and_404(monkeypatch, tmp_path):
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    root_handler = _make_handler(handler_cls, "/")
    root_handler.do_GET()
    assert root_handler.responses == [200]
    assert b"path=" in root_handler.wfile.getvalue()

    class FakeFiles:
        def joinpath(self, name):
            return self

        def read_bytes(self):
            return b"png-bytes"

    monkeypatch.setattr(ui_server.resources, "files", lambda package: FakeFiles())
    asset_handler = _make_handler(handler_cls, "/assets/safedeps-logo.png")
    asset_handler.do_GET()
    assert asset_handler.responses == [200]
    assert asset_handler.wfile.getvalue() == b"png-bytes"

    missing_handler = _make_handler(handler_cls, "/missing")
    missing_handler.do_GET()
    assert missing_handler.errors == [404]


def test_ui_handler_post_scan_runs_pipeline_and_renders_notice(monkeypatch, tmp_path):
    calls = []

    def fake_scan(**kwargs):
        calls.append(kwargs)
        return ScanResult(True, [], {}), tmp_path / "security-artifacts"

    monkeypatch.setattr(ui_server, "run_scan_pipeline", fake_scan)
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    body = f"path={tmp_path}&fail_on=HIGH&out=artifacts&online_audit=on&sarif=a.sarif"
    handler = _make_handler(handler_cls, "/scan", body)
    handler.do_POST()

    assert handler.responses == [200]
    assert calls[0]["root"] == tmp_path
    assert calls[0]["out"] == "artifacts"
    assert calls[0]["online_audit"] is True
    assert calls[0]["sarif"] == "a.sarif"
    assert b"Scan completed" in handler.wfile.getvalue()


def test_ui_handler_post_explain_unknown_rule_renders_error(monkeypatch, tmp_path):
    monkeypatch.setattr(
        ui_server,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    handler = _make_handler(handler_cls, "/explain", f"path={tmp_path}&rule=unknown_rule")
    handler.do_POST()

    assert handler.responses == [200]
    assert b"Unknown finding rule" in handler.wfile.getvalue()


def test_ui_handler_post_baseline_and_approve_render_notices(monkeypatch, tmp_path):
    monkeypatch.setattr(
        ui_server,
        "write_baseline_file",
        lambda root, report_rel, output_rel: (2, root / output_rel),
    )
    monkeypatch.setattr(
        ui_server,
        "upsert_approval_entry",
        lambda root, baseline_rel, manager, rule, package, file_value, expires: (
            False,
            f"{manager}/{rule} package={package} file={file_value} expires={expires}",
        ),
    )
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    baseline_handler = _make_handler(
        handler_cls,
        "/baseline",
        f"path={tmp_path}&report=report.json&baseline_output=.safedeps/baseline.json",
    )
    baseline_handler.do_POST()
    assert baseline_handler.responses == [200]
    assert b"Baseline written" in baseline_handler.wfile.getvalue()

    approve_handler = _make_handler(
        handler_cls,
        "/approve",
        (
            f"path={tmp_path}&baseline_file=.safedeps/baseline.json&manager=pip"
            "&approve_rule=floating_version&package=requests&file_value=requirements.txt&expires=2099-01-01"
        ),
    )
    approve_handler.do_POST()
    assert approve_handler.responses == [200]
    assert b"Added approval" in approve_handler.wfile.getvalue()


def test_ui_handler_post_policy_intelligence_and_deps(monkeypatch, tmp_path):
    monkeypatch.setattr(ui_server, "apply_policy_quick_update", lambda *args, **kwargs: "policy updated")
    monkeypatch.setattr(ui_server, "create_intelligence_templates", lambda root: None)
    monkeypatch.setattr(ui_server, "load_intelligence_into_state", lambda state, root: state)
    monkeypatch.setattr(ui_server, "save_intelligence_from_state", lambda root, state: None)
    monkeypatch.setattr(ui_server, "get_protection_scope", lambda root: "project")
    monkeypatch.setattr(
        ui_server,
        "apply_dependency_action",
        lambda **kwargs: ("dependency changed", "command output"),
    )
    monkeypatch.setattr(
        ui_server,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    policy_handler = _make_handler(handler_cls, "/policy", f"path={tmp_path}&policy_action=add_deny")
    policy_handler.do_POST()
    assert b"policy updated" in policy_handler.wfile.getvalue()

    template_handler = _make_handler(handler_cls, "/intelligence", f"path={tmp_path}&intel_action=template")
    template_handler.do_POST()
    assert b"Intelligence templates created" in template_handler.wfile.getvalue()

    save_handler = _make_handler(
        handler_cls,
        "/intelligence",
        f"path={tmp_path}&intel_action=save&vuln_feed_json={{}}&metadata_cache_json={{}}",
    )
    save_handler.do_POST()
    assert b"Intelligence files saved" in save_handler.wfile.getvalue()

    deps_handler = _make_handler(
        handler_cls,
        "/deps",
        (
            f"path={tmp_path}&dep_runtime_scope=project&dep_manager=pip&dep_action=install"
            "&dep_package=requests&dep_version=1.0.0&dep_mode=manual&dep_approved=on"
        ),
    )
    deps_handler.do_POST()
    assert b"dependency changed" in deps_handler.wfile.getvalue()
    assert b"command output" in deps_handler.wfile.getvalue()


def test_ui_handler_post_setup_runs_setup_scan_and_reports_shell_status(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ui_server, "cmd_setup", lambda args: calls.append(("setup", args)))
    monkeypatch.setattr(ui_server, "get_protection_scope", lambda root: "project")
    monkeypatch.setattr(ui_server, "get_current_shell_guard_status", lambda root: "ACTIVE")
    monkeypatch.setattr(
        ui_server,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    handler_cls = _capture_handler(monkeypatch, tmp_path)

    handler = _make_handler(handler_cls, "/setup", f"path={tmp_path}&fail_on=MEDIUM")
    handler.do_POST()

    assert handler.responses == [200]
    assert calls[0][0] == "setup"
    assert calls[0][1].path == str(tmp_path)
    assert calls[0][1].fail_on == "MEDIUM"
    assert b"Setup completed" in handler.wfile.getvalue()
    assert b"Current shell wrapper status: ACTIVE" in handler.wfile.getvalue()


def test_ui_handler_post_guard_project_scope_refreshes_system_setup(monkeypatch, tmp_path):
    class SystemInstallMode(FakeInstallMode):
        label = "system"
        is_system_install = True

    calls = []
    monkeypatch.setattr(ui_server, "cmd_setup", lambda args: calls.append(("setup", args)))
    monkeypatch.setattr(ui_server, "get_protection_scope", lambda root: "project")
    monkeypatch.setattr(
        ui_server,
        "apply_guard_toggle",
        lambda root, action, install_scope=None: f"guard {action} {install_scope}",
    )
    monkeypatch.setattr(
        ui_server,
        "run_scan_pipeline",
        lambda **kwargs: (ScanResult(True, [], {}), tmp_path / "security-artifacts"),
    )
    handler_cls = _capture_handler(monkeypatch, tmp_path, install_mode=SystemInstallMode())

    handler = _make_handler(
        handler_cls,
        "/guard",
        f"path={tmp_path}&fail_on=HIGH&guard_action=set_scope_project",
    )
    handler.do_POST()

    assert handler.responses == [200]
    assert calls[0][0] == "setup"
    assert calls[0][1].install_scope == "system"
    assert b"Project guard setup completed" in handler.wfile.getvalue()
    assert b"guard set_scope_project system" in handler.wfile.getvalue()


def test_ui_handler_send_bytes_ignores_broken_client_connection(monkeypatch, tmp_path):
    handler_cls = _capture_handler(monkeypatch, tmp_path)
    handler = _make_handler(handler_cls, "/")

    class BrokenWriter:
        def write(self, data):
            raise BrokenPipeError

    handler.wfile = BrokenWriter()

    handler._send_bytes(b"hello", "text/plain")

    assert handler.responses == [200]
    assert ("Content-Type", "text/plain") in handler.headers_sent


def test_ui_handler_post_unknown_path_returns_404(monkeypatch, tmp_path):
    handler_cls = _capture_handler(monkeypatch, tmp_path)
    handler = _make_handler(handler_cls, "/unknown", f"path={tmp_path}")

    handler.do_POST()

    assert handler.errors == [404]
