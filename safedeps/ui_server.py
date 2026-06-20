from __future__ import annotations

import argparse
import os
import threading
import webbrowser
from importlib import resources
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .constants import RULE_EXPLAINERS, SEVERITY_ORDER
from .dependency_actions import apply_dependency_action, apply_policy_quick_update, _format_dependency_ui_error
from .exceptions import upsert_approval_entry, write_baseline_file
from .runtime import _default_ui_workspace, _install_mode, _normalize_project_path, _resolve_ui_start_path
from .scan import run_scan_pipeline
from .ui_render import render_ui_page
from .ui_state import (
    _ui_state_from_form,
    create_intelligence_templates,
    load_intelligence_into_state,
    save_intelligence_from_state,
)
from . import guard as _guard

cmd_setup = _guard.cmd_setup
apply_guard_toggle = _guard.apply_guard_toggle
get_protection_scope = _guard.get_protection_scope
get_current_shell_guard_status = _guard.get_current_shell_guard_status

def cmd_ui_shortcut(args):
    if os.name != "nt":
        print("Shortcut generation is currently available on Windows only.")
        return 2
    workspace = _default_ui_workspace()
    workspace.mkdir(parents=True, exist_ok=True)
    user_profile = os.environ.get("USERPROFILE") or str(Path.home())
    desktop = Path(user_profile) / "Desktop"
    desktop.mkdir(parents=True, exist_ok=True)
    shortcut_path = desktop / "SafeDeps UI.bat"
    content = (
        "@echo off\r\n"
        "setlocal\r\n"
        f"cd /d \"{workspace}\"\r\n"
        "safedeps ui . --host 127.0.0.1 --port 5200 --open-browser\r\n"
    )
    shortcut_path.write_text(content, encoding="utf-8")
    print(f"Desktop launcher created: {shortcut_path}")
    print("Double-click the .bat file to open SafeDeps UI.")
    return 0

def cmd_ui(args):
    host = args.host
    port = args.port
    start_path = _resolve_ui_start_path(args.path)
    default_fail_on = args.fail_on
    setup_note = ""
    install_scope_arg = getattr(args, "install_scope", "auto")
    install_mode = _install_mode(start_path, None if install_scope_arg == "auto" else install_scope_arg)

    def render_page(path: Path, fail_on: str, **kwargs):
        return render_ui_page(path, fail_on, install_scope=install_mode.label, **kwargs)

    def _require_existing_project_dir(path: Path, purpose: str):
        if not path.exists() or not path.is_dir():
            raise ValueError(f"{purpose}: path must be an existing directory.")
        return path

    def enforce_project_scope_if_needed(path: Path):
        _install_mode(path, install_mode.label).enforce_project_state(path)

    class UIHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/assets/safedeps-logo.png":
                try:
                    logo_bytes = resources.files("safedeps.assets").joinpath("safedeps_logo.png").read_bytes()
                except Exception:
                    self.send_error(404)
                    return
                self._send_bytes(logo_bytes, "image/png")
                return
            if self.path != "/":
                self.send_error(404)
                return
            try:
                _require_existing_project_dir(start_path, "Project path")
                enforce_project_scope_if_needed(start_path)
                body = render_page(start_path, default_fail_on)
            except Exception as e:
                body = render_page(start_path, default_fail_on, error=str(e))
            self._send_html(body)

        def do_POST(self):
            if self.path not in ("/scan", "/explain", "/baseline", "/approve", "/setup", "/intelligence", "/policy", "/guard", "/deps"):
                self.send_error(404)
                return
            content_len = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_len).decode("utf-8")
            form = parse_qs(payload)
            raw_scan_path = (form.get("path", [str(start_path)])[0] or str(start_path)).strip()
            scan_path = _normalize_project_path(Path(raw_scan_path or str(start_path)).resolve())
            _require_existing_project_dir(scan_path, "Project path")
            fail_on = (form.get("fail_on", [default_fail_on])[0] or default_fail_on).upper()
            ui_state = _ui_state_from_form(form, scan_path, fail_on)

            def _refresh_project_setup_for_system_scope():
                if not install_mode.is_system_install:
                    return
                cmd_setup(
                    argparse.Namespace(
                        path=str(scan_path),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        force=True,
                        install_scope=install_mode.label,
                        protection_scope=get_protection_scope(scan_path),
                    )
                )

            try:
                enforce_project_scope_if_needed(scan_path)
                if self.path == "/scan":
                    out = form.get("out", ["security-artifacts"])[0] or "security-artifacts"
                    online_audit = form.get("online_audit", ["off"])[0] == "on"
                    result, outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=out,
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=online_audit,
                        sarif=form.get("sarif", [""])[0],
                        cyclonedx=form.get("cyclonedx", [""])[0],
                        spdx=form.get("spdx", [""])[0],
                        html=form.get("html", [""])[0],
                    )
                    body = render_page(scan_path, fail_on, result=result, outdir=outdir, notice="Scan completed.", ui_state=ui_state)
                elif self.path == "/explain":
                    rule = (form.get("rule", [""])[0] or "").strip().upper()
                    text = RULE_EXPLAINERS.get(rule)
                    if not text:
                        raise ValueError(f"Unknown finding rule: {rule}")
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=f"{rule}: {text}", ui_state=ui_state)
                elif self.path == "/baseline":
                    report_rel = form.get("report", ["security-artifacts/safedeps-report.json"])[0] or "security-artifacts/safedeps-report.json"
                    output_rel = form.get("baseline_output", [".safedeps/vuln-baseline.json"])[0] or ".safedeps/vuln-baseline.json"
                    count, output_path = write_baseline_file(scan_path, report_rel, output_rel)
                    body = render_page(scan_path, fail_on, notice=f"Baseline written: {output_path} ({count} entries)", ui_state=ui_state)
                elif self.path == "/approve":
                    updated, msg = upsert_approval_entry(
                        scan_path,
                        baseline_rel=form.get("baseline_file", [".safedeps/vuln-baseline.json"])[0] or ".safedeps/vuln-baseline.json",
                        manager=(form.get("manager", [""])[0] or "").strip(),
                        rule=(form.get("approve_rule", [""])[0] or "").strip().upper(),
                        package=(form.get("package", [""])[0] or "").strip(),
                        file_value=(form.get("file_value", [""])[0] or "").strip(),
                        expires=(form.get("expires", [""])[0] or "").strip(),
                    )
                    action = "Updated" if updated else "Added"
                    body = render_page(scan_path, fail_on, notice=f"{action} approval: {msg}", ui_state=ui_state)
                elif self.path == "/setup":
                    cmd_setup(
                        argparse.Namespace(
                            path=str(scan_path),
                            fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                            force=True,
                            install_scope=install_mode.label,
                            protection_scope=get_protection_scope(scan_path),
                        )
                    )
                    shell_guard_status = get_current_shell_guard_status(scan_path)
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_page(
                        scan_path,
                        fail_on,
                        result=refreshed_result,
                        outdir=refreshed_outdir,
                        notice=(
                            f"Setup completed for {scan_path} (equivalent to: safedeps setup {scan_path}). "
                            "Activate this shell with: source .safedeps/activate.sh (bash) or . .safedeps/activate.ps1 (PowerShell). "
                            f"Current shell wrapper status: {shell_guard_status}"
                        ),
                        ui_state=ui_state,
                    )
                elif self.path == "/guard":
                    guard_action = (form.get("guard_action", [""])[0] or "").strip().lower()
                    setup_note = ""
                    ok_guard_action, guard_action_error = _install_mode(scan_path, install_mode.label).can_set_guard_action(guard_action)
                    if not ok_guard_action:
                        raise ValueError(guard_action_error)
                    enforce_project_scope_if_needed(scan_path)
                    if guard_action == "set_scope_project" and not scan_path.exists():
                        raise ValueError("Select a valid project root path before switching to Project scope.")
                    if guard_action == "set_scope_project":
                        _refresh_project_setup_for_system_scope()
                        setup_note = "Project guard setup completed for the selected root. "
                    notice_text = apply_guard_toggle(scan_path, guard_action, install_scope=install_mode.label)
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=f"{setup_note}{notice_text}", ui_state=ui_state)
                elif self.path == "/deps":
                    action_scope = (form.get("dep_runtime_scope", [""])[0] or "").strip().lower()
                    action_scope = _install_mode(scan_path, install_mode.label).action_scope(
                        action_scope,
                        get_protection_scope(scan_path),
                    )
                    notice_text, action_output = apply_dependency_action(
                        root=scan_path,
                        manager=(form.get("dep_manager", [""])[0] or "").strip().lower(),
                        action=(form.get("dep_action", [""])[0] or "").strip().lower(),
                        package=(form.get("dep_package", [""])[0] or "").strip(),
                        version=(form.get("dep_version", [""])[0] or "").strip(),
                        mode=(form.get("dep_mode", [""])[0] or "manual").strip().lower(),
                        approved=(form.get("dep_approved", ["off"])[0] == "on"),
                        approval_note="",
                        action_scope=action_scope,
                    )
                    ui_state["dependency_output"] = action_output
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=notice_text, ui_state=ui_state)
                else:
                    if self.path == "/policy":
                        notice_text = apply_policy_quick_update(
                            scan_path,
                            action=(form.get("policy_action", [""])[0] or "").strip(),
                            manager=(form.get("policy_manager", [""])[0] or "").strip(),
                            package=(form.get("policy_package", [""])[0] or "").strip(),
                            registry=(form.get("policy_registry", [""])[0] or "").strip(),
                            policy_path=(form.get("policy_path", [""])[0] or "").strip(),
                        )
                        body = render_page(scan_path, fail_on, notice=notice_text, ui_state=ui_state)
                    else:
                        action = (form.get("intel_action", ["save"])[0] or "save").strip().lower()
                        if action == "template":
                            create_intelligence_templates(scan_path)
                            ui_state = load_intelligence_into_state(ui_state, scan_path)
                            body = render_page(scan_path, fail_on, notice="Intelligence templates created.", ui_state=ui_state)
                        else:
                            save_intelligence_from_state(scan_path, ui_state)
                            body = render_page(scan_path, fail_on, notice="Intelligence files saved and validated.", ui_state=ui_state)
            except Exception as e:
                refreshed_result = None
                refreshed_outdir = None
                try:
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                except Exception:
                    pass
                err_text = str(e)
                if self.path == "/deps":
                    ui_state["dependency_output"] = f"Error: {_format_dependency_ui_error(err_text)}"
                    err_text = _format_dependency_ui_error(err_text)
                else:
                    err_text = _format_dependency_ui_error(err_text)
                body = render_page(
                    scan_path,
                    fail_on,
                    result=refreshed_result,
                    outdir=refreshed_outdir,
                    error=err_text,
                    ui_state=ui_state,
                )
            self._send_html(body)

        def _send_html(self, body: str):
            data = body.encode("utf-8")
            self._send_bytes(data, "text/html; charset=utf-8")

        def _send_bytes(self, data: bytes, content_type: str):
            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                return

        def log_message(self, format, *args):
            return

    server = None
    bind_port = int(port)
    last_err = None
    first_error = None
    for p in range(bind_port, bind_port + 25):
        try:
            server = ThreadingHTTPServer((host, p), UIHandler)
            bind_port = p
            break
        except OSError as e:
            last_err = e
            if p == bind_port and first_error is None:
                first_error = e
            continue
    if server is None:
        raise last_err if last_err else RuntimeError("Unable to bind UI server port.")
    if bind_port != int(port) and first_error is not None:
        print(f"SafeDeps UI port {port} not available ({first_error}); using {bind_port}.")
    url = f"http://{host}:{bind_port}/"
    print(f"SafeDeps UI running at {url}")
    print(f"Workspace: {start_path}")
    print("Press Ctrl+C to stop.")
    if args.open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
