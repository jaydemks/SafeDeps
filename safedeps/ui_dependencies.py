from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .constants import SEVERITY_ORDER
from .models import ScanResult
from .reports import _html_escape, _js_escape, _unique_components
from .runtime import (
    _detect_project_runtime_python,
    _has_project_runtime_candidates,
    _install_mode,
)


def render_findings_table(result: ScanResult):
    if not result.findings:
        return "<p>No findings.</p>"
    rows = []
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        rows.append(
            "<tr>"
            f"<td>{_html_escape(f.severity)}</td>"
            f"<td>{_html_escape(f.manager)}</td>"
            f"<td>{_html_escape(f.rule)}</td>"
            f"<td>{_html_escape(f.package)}</td>"
            f"<td>{_html_escape(f.file)}</td>"
            f"<td>{_html_escape(f.message)}</td>"
            f"<td><button class='pick' type='button' onclick=\"setApprovalFields('{_js_escape(f.manager)}','{_js_escape(f.rule)}','{_js_escape(f.package)}','{_js_escape(f.file)}')\">Use For Approval</button></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Manager</th><th>Rule</th><th>Package</th><th>File</th><th>Message</th><th>Action</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )

def _is_runtime_component(component: dict) -> bool:
    scope = str(component.get("scope", "")).strip().lower()
    return scope.startswith("runtime:")

def render_dependency_table(
    result: ScanResult,
    fail_on: str,
    root: Path,
    protection_scope: str = "project",
    installation_scope: str | None = None,
):
    components = _unique_components(result.sbom.get("components", []))
    mode = _install_mode(root, installation_scope)
    project_py = mode.project_runtime_python()
    system_runtime: list[dict] = []
    project_runtime: list[dict] = []

    if mode.is_system_install:
        system_runtime = collect_runtime_components(
            root,
            python_executable=mode.system_runtime_python(),
            runtime_scope="runtime:system",
            fallback_to_process=False,
        )
        if project_py and _has_project_runtime_candidates(root):
            project_runtime = collect_runtime_components(
                root,
                python_executable=project_py,
                runtime_scope="runtime:project",
                fallback_to_process=False,
                local_only=True,
            )
    else:
        if project_py:
            project_runtime = collect_runtime_components(
                root,
                python_executable=project_py,
                runtime_scope="runtime:project",
                fallback_to_process=False,
                local_only=True,
            )

    if system_runtime:
        components.extend(system_runtime)
    if project_runtime:
        components.extend(project_runtime)
    if system_runtime or project_runtime:
        components = _unique_components(components)

    if not components:
        return "<p class='hint'>No dependencies detected in the current scan.</p>"

    def _runtime_bucket(component: dict) -> str:
        scope = str(component.get("scope", "")).strip().lower()
        if scope.startswith("runtime:project"):
            return "project"
        if scope.startswith("runtime:system"):
            return "system"
        if scope.startswith("runtime:"):
            return "system"
        return ""

    if mode.is_project_install:
        project_only_components = [
            c for c in components
            if not _is_runtime_component(c) or _runtime_bucket(c) == "project"
        ]
        project_table = _render_dependency_rows_table(result, fail_on, project_only_components)
        if project_table:
            return (
                "<details open class='card' style='margin-top:12px;'>"
                "<summary style='cursor:pointer; font-weight:700;' title='Dependencies detected for this project environment.'>Project dependencies</summary>"
                f"<div id='project-deps-wrap'>{project_table}</div></details>"
            )
        return "<p class='hint'>No project dependencies detected for this scope.</p>"

    project_components = [c for c in components if not _is_runtime_component(c)]
    runtime_components = [c for c in components if _is_runtime_component(c)]
    system_runtime_components = [
        c for c in runtime_components
        if _runtime_bucket(c) == "system"
    ]
    project_runtime_components = [
        c for c in runtime_components
        if _runtime_bucket(c) == "project"
    ]
    system_runtime_table = _render_dependency_rows_table(result, fail_on, system_runtime_components) if system_runtime_components else ""
    project_runtime_table = _render_dependency_rows_table(result, fail_on, project_runtime_components) if project_runtime_components else ""

    project_table = _render_dependency_rows_table(result, fail_on, project_components)
    if project_table:
        out = (
            "<details open class='card' style='margin-top:12px;'>"
            "<summary style='cursor:pointer; font-weight:700;' title='Dependencies declared in the selected project files.'>Project dependencies</summary>"
            f"<div id='project-deps-wrap'>{project_table}</div></details>"
        )
    else:
        out = ""

    if project_runtime_table:
        out += (
            "<details class='card' style='margin-top:12px;'>"
            "<summary style='cursor:pointer; font-weight:700;' title='Project runtime environment dependencies for the selected project path.'>Project runtime dependencies</summary>"
            f"<div id='project-runtime-deps-wrap'>{project_runtime_table}</div></details>"
        )

    if system_runtime_table:
        out += (
            "<details class='card' style='margin-top:12px;'>"
            "<summary style='cursor:pointer; font-weight:700;' title='System-wide runtime dependencies for the active SafeDeps interpreter.'>System/runtime dependencies</summary>"
            f"<div id='runtime-deps-wrap'>{system_runtime_table}</div></details>"
        )

    if out:
        return out

    return "<p class='hint'>No dependencies detected for this scope.</p>"

def _render_dependency_rows_table(result: ScanResult, fail_on: str, components: list[dict]):
    if not components:
        return "<p class='hint'>No dependencies detected for this scope.</p>"

    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["HIGH"])
    by_pkg: dict[tuple[str, str], dict[str, Any]] = {}
    for c in components:
        manager = str(c.get("manager", "")).strip()
        name = str(c.get("name", "")).strip()
        scope = str(c.get("scope", "")).strip().lower()
        version = str(c.get("version", "")).strip()
        if not manager or not name:
            continue
        key = (manager.lower(), name.lower())
        if key not in by_pkg:
            by_pkg[key] = {
                "manager": manager,
                "name": name,
                "declared_version": "",
                "installed_version": "",
                "runtime_scope": "",
                "scopes": set(),
                "findings": [],
            }
        by_pkg[key]["scopes"].add(scope)
        if scope.startswith("runtime:"):
            if not by_pkg[key]["installed_version"]:
                by_pkg[key]["installed_version"] = version
            if scope.startswith("runtime:project"):
                by_pkg[key]["runtime_scope"] = "project"
            elif not by_pkg[key]["runtime_scope"]:
                by_pkg[key]["runtime_scope"] = "system"
        elif not by_pkg[key]["declared_version"]:
            by_pkg[key]["declared_version"] = version

    for f in result.findings:
        if not f.package:
            continue
        finding_manager = str(f.manager or "").lower()
        finding_package = str(f.package or "").lower()
        target_key = (finding_manager, finding_package)
        if target_key not in by_pkg:
            by_pkg[target_key] = {
                "manager": str(f.manager or "").strip() or "unknown",
                "name": str(f.package or "").strip(),
                "declared_version": "",
                "installed_version": "",
                "runtime_scope": "",
                "scopes": set(),
                "findings": [],
            }
        by_pkg[target_key]["findings"].append(f)

    rows = []
    for dep in sorted(by_pkg.values(), key=lambda x: (x["manager"].lower(), x["name"].lower())):
        findings = dep["findings"]
        worst = "OK"
        if findings:
            worst = max(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0)).severity
        status = "Blocked" if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold and f.severity != "INFO" for f in findings) else "Installed"
        if not findings:
            status = "Approved/Installed"
        rules = ", ".join(sorted({f.rule for f in findings})) if findings else "-"
        primary = findings[0] if findings else None
        quick = ""
        dep_scope = str(dep.get("runtime_scope", "")).strip().lower()
        scope_attr = ";".join(sorted(dep.get("scopes", set())))
        if primary:
            approve_btn = (
                f"<button class='pick' type='button' "
                f"onclick=\"quickApprove('{_js_escape(primary.manager)}','{_js_escape(primary.rule)}','{_js_escape(primary.package)}','{_js_escape(primary.file)}')\">"
                "Approve (+30 days)</button>"
            )
            uninstall_btn = (
                f"<button class='ghost' type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','uninstall','{_js_escape(dep['name'])}','manual','{_js_escape(dep_scope)}')\">"
                "Uninstall</button>"
            )
            safe_update_btn = (
                f"<button type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','update','{_js_escape(dep['name'])}','auto','{_js_escape(dep_scope)}')\">"
                "Safe Update</button>"
            )
            quick = f"<div class='quick-actions'>{approve_btn}{uninstall_btn}{safe_update_btn}</div>"
        else:
            uninstall_btn = (
                f"<button class='ghost' type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','uninstall','{_js_escape(dep['name'])}','manual','{_js_escape(dep_scope)}')\">"
                "Uninstall</button>"
            )
            safe_update_btn = (
                f"<button type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','update','{_js_escape(dep['name'])}','auto','{_js_escape(dep_scope)}')\">"
                "Safe Update</button>"
            )
            quick = f"<div class='quick-actions'><span class='action-slot' aria-hidden='true'></span>{uninstall_btn}{safe_update_btn}</div>"
        rows.append(
            f"<tr data-manager=\"{_html_escape(dep['manager'].lower())}\" data-package=\"{_html_escape(dep['name'].lower())}\" data-scope=\"{_html_escape(scope_attr)}\" data-runtime-scope=\"{_html_escape(dep_scope)}\">"
            f"<td>{_html_escape(dep['manager'])}</td>"
            f"<td>{_html_escape(dep['name'])}</td>"
            f"<td>{_html_escape(dep['declared_version'] or '-')}</td>"
            f"<td>{_html_escape(dep['installed_version'] or '-')}</td>"
            f"<td>{_html_escape(worst)}</td>"
            f"<td>{_html_escape(status)}</td>"
            f"<td>{_html_escape(rules)}</td>"
            f"<td>{quick}</td>"
            "</tr>"
        )

    return (
        "<div class='dependency-table-shell'>"
        "<div class='dependency-filter-bar'>"
        "<label class='dependency-filter-label'>Filter dependencies</label>"
        "<input type='search' data-dependency-filter='1' class='dependency-filter-input' "
        "placeholder='Package, manager, version, severity, status...' aria-label='Filter dependencies in this list' />"
        f"<span class='dependency-filter-count' data-filter-count>{len(rows)} dependencies</span>"
        "</div>"
        "<table><thead><tr>"
        "<th>Manager</th><th>Package</th><th>Declared</th><th>Installed</th><th>Worst Severity</th><th>Status</th><th>Rules</th><th>Quick Action</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        "</div>"
    )

def collect_runtime_components(
    root: Path,
    *,
    python_executable: str | None = None,
    runtime_scope: str = "runtime",
    fallback_to_process: bool = False,
    local_only: bool = False,
):
    if not python_executable:
        python_executable = _detect_project_runtime_python(root)
    if not python_executable and not fallback_to_process:
        return []
    if not python_executable:
        python_executable = str(Path(sys.executable).resolve())
    scope_prefix = (runtime_scope or "runtime").strip().rstrip(":")
    if not scope_prefix:
        scope_prefix = "runtime"
    out = []
    # Python runtime packages from current interpreter environment.
    try:
        pip_cmd = [python_executable, "-m", "pip", "list", "--format", "json"]
        if local_only:
            pip_cmd.append("--local")
        proc = subprocess.run(
            pip_cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=8,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout or "[]")
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", "")).strip()
                    ver = str(item.get("version", "")).strip()
                    if name:
                        out.append({
                            "type": "library",
                            "manager": "pip",
                            "name": name,
                            "version": ver,
                            "scope": f"{scope_prefix}:pip",
                        })
    except Exception:
        pass
    if not out:
        try:
            proc = subprocess.run(
                [
                    python_executable,
                    "-c",
                    (
                        "import json, importlib.metadata as m; "
                        "print(json.dumps([{'name': d.metadata.get('Name') or d.metadata.get('Summary') or '', "
                        "'version': d.version} for d in m.distributions()]))"
                    ),
                ],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout or "[]")
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("name", "")).strip()
                        ver = str(item.get("version", "")).strip()
                        if name:
                            out.append({
                                "type": "library",
                                "manager": "pip",
                                "name": name,
                                "version": ver,
                                "scope": f"{scope_prefix}:pip",
                            })
        except Exception:
            pass

    # npm runtime packages if a Node project exists.
    try:
        if (root / "package.json").exists():
            proc = subprocess.run(
                ["npm", "ls", "--depth=0", "--json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout or "{}")
                deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
                if isinstance(deps, dict):
                    for name, meta in deps.items():
                        if not isinstance(name, str):
                            continue
                        ver = ""
                        if isinstance(meta, dict):
                            ver = str(meta.get("version", "")).strip()
                        out.append({
                            "type": "library",
                            "manager": "npm",
                            "name": name.strip(),
                            "version": ver,
                            "scope": f"{scope_prefix}:npm",
                        })
    except Exception:
        pass

    return out

def render_pip_guard_panel(result: ScanResult, fail_on: str):
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["HIGH"])
    pip_blockers = [
        f for f in result.findings
        if f.manager == "pip" and f.severity != "INFO" and SEVERITY_ORDER.get(f.severity, 0) >= threshold
    ]
    if not pip_blockers:
        return (
            "<div class='notice'>"
            f"Pip install guard: no blocking pip findings at threshold {fail_on}."
            "</div>"
        )
    items = "".join(
        f"<li>{_html_escape(f.package or '(unknown)')} - {_html_escape(f.rule)} - {_html_escape(f.message)}</li>"
        for f in pip_blockers
    )
    return (
        "<div class='error'>"
        f"Pip install guard: {len(pip_blockers)} blocking finding(s) at threshold {fail_on}."
        f"<ul>{items}</ul>"
        "</div>"
    )
