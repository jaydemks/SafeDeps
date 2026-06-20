from __future__ import annotations

from pathlib import Path

from . import guard as _guard
from .constants import SEVERITY_ORDER
from .models import ScanResult
from .reports import _html_escape
from .runtime import (
    _install_mode,
)
from .ui_assets import UI_CSS
from .ui_dependencies import (
    render_dependency_table,
    render_findings_table,
    render_pip_guard_panel,
)
from .ui_state import default_ui_state, load_intelligence_into_state

get_setup_status = _guard.get_setup_status
get_guard_mode_status = _guard.get_guard_mode_status
get_protection_scope = _guard.get_protection_scope
get_current_shell_guard_status = _guard.get_current_shell_guard_status
_is_auto_guard_enabled = _guard._is_auto_guard_enabled

def render_ui_page(
    scan_path: Path,
    fail_on: str,
    result: ScanResult | None = None,
    outdir: Path | None = None,
    error: str = "",
    notice: str = "",
    ui_state: dict | None = None,
    install_scope: str | None = None,
):
    state = ui_state or default_ui_state(scan_path, fail_on)
    state = load_intelligence_into_state(state, scan_path)
    setup_status = get_setup_status(scan_path)
    guard_status = get_guard_mode_status(scan_path)
    install_mode = _install_mode(scan_path, install_scope)
    install_scope = install_mode.label
    install_scope_forbidden_global = not install_mode.global_scope_available
    scope_mode = get_protection_scope(scan_path)
    auto_guard_enabled = _is_auto_guard_enabled(scan_path)
    runtime_python = install_mode.system_runtime_python()
    project_runtime_python = install_mode.project_runtime_python() or "Not detected"
    deps_html = render_dependency_table(
        result,
        state["fail_on"],
        scan_path,
        scope_mode,
        installation_scope=install_scope,
    ) if result is not None else "<p class='hint'>Run a scan to load dependencies and quick actions.</p>"
    shell_guard_status = get_current_shell_guard_status(scan_path)
    options = "".join(
        f"<option value=\"{s}\"{' selected' if s == state['fail_on'] else ''}>{s}</option>"
        for s in SEVERITY_ORDER
    )
    status_html = ""
    if error:
        error_prefix = "Scan error"
        action_error_starts = (
            "Uninstall blocked:",
            "Update blocked:",
            "Blocked:",
            "pip install failed:",
            "pip update failed:",
            "pip uninstall failed:",
            "npm install failed:",
            "npm update failed:",
            "npm uninstall failed:",
        )
        if any(str(error).startswith(prefix) for prefix in action_error_starts):
            error_prefix = "Dependency action error"
        status_html = f"<div class='error'>{error_prefix}: {_html_escape(error)}</div>"
    elif notice:
        status_html = f"<div class='notice'>{_html_escape(notice)}</div>"
    elif result is not None:
        status_html = (
            f"<div class='status {'ok' if result.ok else 'fail'}'>"
            f"Status: {'PASS' if result.ok else 'FAIL'} | Findings: {len(result.findings)} | "
            f"Components: {len(result.sbom.get('components', []))} | Artifacts: {_html_escape(str(outdir or ''))}"
            "</div>"
        )
    checked = " checked" if state.get("online_audit") else ""
    logo_html = "<img src=\"/assets/safedeps-logo.png\" alt=\"SafeDeps logo\" />"
    project_action_help = ""
    if install_scope_forbidden_global:
        project_action_help = "SafeDeps is installed in a virtual environment; Global scope is locked."
    scope_help_hint = ""
    if project_action_help:
        scope_help_hint = f"<div class='hint'>{project_action_help}</div>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeDeps UI</title>
  <style>
{UI_CSS}
  </style>
</head>
<body data-page="overview">
  <div class="app-shell">
    <aside class="sidebar" aria-label="SafeDeps navigation">
      <div class="sidebar-top">
        <div class="brand-mark">
          <div class="brand-icon">{logo_html}</div>
          <div class="brand-copy">
            <div class="brand-name">SafeDeps</div>
            <div class="brand-sub">Control Center</div>
          </div>
        </div>
      </div>
      <nav class="nav-list">
        <button type="button" class="nav-item active" data-page-target="overview" title="Dashboard status, setup, Auto Guard and scope controls."><span class="nav-icon">OV</span><span class="nav-label">Overview</span></button>
        <button type="button" class="nav-item" data-page-target="scan" data-scroll-target="section-scan" title="Run SafeDeps scans and configure report outputs."><span class="nav-icon">SC</span><span class="nav-label">Run Scan</span></button>
        <button type="button" class="nav-item" data-page-target="scan" data-scroll-target="section-deps-view" title="Review dependencies, findings, and quick actions."><span class="nav-icon">DP</span><span class="nav-label">Dependencies</span></button>
        <button type="button" class="nav-item" data-page-target="scan" data-scroll-target="section-deps-manage" title="Install, update, uninstall, and test guarded package actions."><span class="nav-icon">MG</span><span class="nav-label">Manage</span></button>
        <button type="button" class="nav-item" data-page-target="console" title="Read captured dependency action output."><span class="nav-icon">CN</span><span class="nav-label">Console</span></button>
        <button type="button" class="nav-item" data-page-target="exceptions" title="Explain rules and manage baselines or temporary approvals."><span class="nav-icon">EX</span><span class="nav-label">Exceptions</span></button>
        <button type="button" class="nav-item" data-page-target="policy" title="Edit registry allowlists and package deny rules."><span class="nav-icon">PL</span><span class="nav-label">Policy</span></button>
        <button type="button" class="nav-item" data-page-target="intel" title="Maintain local vulnerability and metadata intelligence files."><span class="nav-icon">IN</span><span class="nav-label">Intelligence</span></button>
      </nav>
      <div class="sidebar-footer">
        <div class="collapse-card">
          <button id="sidebar-toggle-bottom" class="icon-button" type="button" title="Collapse or expand the sidebar." aria-label="Toggle sidebar">&lt;</button>
          <div class="collapse-copy">
            <div class="brand-name">Collapse</div>
            <div class="brand-sub">Icon mode</div>
          </div>
        </div>
      </div>
    </aside>
    <main class="main-panel">
      <header class="topbar">
        <div>
          <div class="page-kicker">Runtime Guard Dashboard</div>
          <h1>SafeDeps Control Center</h1>
          <p class="page-sub">Security-first dependency workflow with guided actions, runtime guard, and policy control.</p>
        </div>
        <div class="top-actions">
          <button id="theme-toggle" type="button" class="ghost" title="Switch between light and dark theme.">Theme</button>
        </div>
      </header>
      <div class="content-area">
      <section class="hero page-section active" id="hero-wrap" data-page="overview">
        <div class="hero-head">
          <div>
            <div class="page-kicker">Live Guard State</div>
            <h2 class="hero-title">Dashboard</h2>
            <p class="hero-sub">Compact guard state, runtime paths, setup actions, and scope controls.</p>
          </div>
        </div>
        <div class="status-grid">
          <div class="status-card" title="Create or refresh SafeDeps wrappers and activation scripts for this project.">
            <div class="status-label">Setup</div>
            <div class="status-value" id="setup-status-line">{_html_escape(setup_status)}</div>
          </div>
          <div class="status-card" title="Shows whether future shell sessions auto-load SafeDeps protection.">
            <div class="status-label">Auto Guard</div>
            <div class="status-value" id="autoguard-status-line">{_html_escape(guard_status)}</div>
          </div>
          <div class="status-card" title="Python interpreter used by SafeDeps for system-scope runtime operations.">
            <div class="status-label">Runtime Python</div>
            <div class="status-value">{_html_escape(runtime_python)}</div>
          </div>
          <div class="status-card" title="Shows whether the current shell is already using SafeDeps wrappers.">
            <div class="status-label">Current Shell</div>
            <div class="status-value" id="shellguard-status-line">{_html_escape(shell_guard_status)}</div>
            <div class="status-sub">{_html_escape(project_runtime_python)}</div>
          </div>
        </div>
        <div class="guard-bar">
          <div class="toolbar">
            <div class="mini-actions">
              <form method="post" autocomplete="off" action="/setup" data-pending="hero-wrap">
                <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
                <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
                <button type="submit" title="Create or refresh SafeDeps wrappers and activation scripts for this project.">Setup Guard</button>
              </form>
              <form method="post" autocomplete="off" action="/guard" data-pending="hero-wrap">
                <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
                <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
                <div class="segmented auto-toggle" role="tablist" aria-label="Auto guard toggle">
                  <button type="submit" name="guard_action" value="enable_auto" class="{'active on' if auto_guard_enabled else ''}" title="Enable auto guard in future Windows shell sessions.">Auto ON</button>
                  <button type="submit" name="guard_action" value="disable_auto" class="{'active off' if not auto_guard_enabled else ''}" title="Disable auto guard in future Windows shell sessions.">Auto OFF</button>
                </div>
              </form>
            </div>
            <form method="post" autocomplete="off" action="/guard" data-pending="hero-wrap">
              <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
              <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
              <div class="segmented" role="tablist" aria-label="Protection scope">
                <button type="submit" name="guard_action" value="set_scope_project" class="{'active' if scope_mode == 'project' else ''}" title="Protect only this project context.">Project</button>
                <button type="submit" name="guard_action" value="set_scope_global" class="{'active' if scope_mode == 'global' else ''}" title="Protect commands globally in this shell profile context." { "disabled" if install_scope_forbidden_global else "" }>Global</button>
              </div>
            </form>
          </div>
          {scope_help_hint}
        </div>
      </section>
      <section class="section page-section" id="section-scan" data-page="scan">
      <div class="section-header">
        <div>
          <h2>Run Scan</h2>
          <p class="sub">Scan a project, choose fail threshold, and optionally export reports without leaving this dashboard.</p>
        </div>
      </div>
      <form method="post" autocomplete="off" action="/scan" id="scan-form" data-ajax="1" data-pending="section-scan">
        <div class="full path-row">
          <label title="Folder to scan.">Project path</label>
          <input id="scan-path-input" name="path" value="{_html_escape(state['path'])}" title="Absolute or relative path to the project root." />
          <button type="button" class="ghost pick" id="browse-project-root" title="Choose the project path inside SafeDeps UI.">Browse</button>
        </div>
        <div><label title="Severity threshold that makes the scan fail.">Fail on</label><select name="fail_on" title="Findings at or above this level mark the scan as failed.">{options}</select></div>
        <div><label title="Where reports and artifacts are written.">Output dir</label><input name="out" value="{_html_escape(state['out'])}" title="Output directory for scan artifacts." /></div>
        <div><label title="Optional custom policy file.">Policy file (optional)</label><input name="policy" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" title="Leave empty to use default policy." /></div>
        <div><label>SARIF path (optional)</label><input name="sarif" value="{_html_escape(state['sarif'])}" placeholder="security-artifacts/safedeps.sarif" /></div>
        <div><label>CycloneDX path (optional)</label><input name="cyclonedx" value="{_html_escape(state['cyclonedx'])}" placeholder="security-artifacts/safedeps.cdx.json" /></div>
        <div><label>SPDX path (optional)</label><input name="spdx" value="{_html_escape(state['spdx'])}" placeholder="security-artifacts/safedeps.spdx.json" /></div>
        <div><label>HTML path (optional)</label><input name="html" value="{_html_escape(state['html'])}" placeholder="security-artifacts/safedeps-report.html" /></div>
        <div class="full actions">
          <label title="Enable extra network-based checks if available."><input type="checkbox" name="online_audit"{checked}> Online audit</label>
          <button type="submit" title="Run scan again with current settings and refresh all sections.">Re-Scan</button>
        </div>
      </form>
      </section>
      <section class="section page-section" id="section-deps-view" data-page="scan">
      <div class="section-header">
        <div>
          <h2>Dependency View And Quick Actions</h2>
          <p class="sub">Review dependencies, blockers, guard status, and approval shortcuts from a single workspace.</p>
        </div>
      </div>
      <div class="card" id="deps-table-wrap">
        <p class="sub">This section becomes interactive after a scan. Use it to quickly trust registries, deny packages, and create approvals with expiration.</p>
        {deps_html}
      </div>
      <div id="status-wrap">{status_html}</div>
      <div id="pip-guard-wrap">{render_pip_guard_panel(result, state["fail_on"]) if result is not None else ""}</div>
      <details class="card" style="margin-top:12px;">
        <summary style="cursor:pointer; font-weight:700;" title="Detailed findings list used for temporary exception workflows.">Advanced Findings (for manual approvals)</summary>
        <div id="findings-wrap">{render_findings_table(result) if result is not None else ""}</div>
      </details>
      </section>
      <section class="section page-section" id="section-deps-manage" data-page="scan">
      <div class="section-header">
        <div>
          <h2>Manage Dependencies</h2>
          <p class="sub">Execute package changes through SafeDeps checks. Example: install colorama with version 0.4.6, or run Safe Update for one package only.</p>
        </div>
      </div>
        <form method="post" autocomplete="off" action="/deps" id="deps-form" data-ajax="1" data-pending="section-deps-manage">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <input type="hidden" id="dep-runtime-scope" name="dep_runtime_scope" value="" />
        <div><label title="Package manager to execute action with.">Manager</label>
          <select name="dep_manager" id="dep-manager">
            <option value="pip">pip</option>
            <option value="npm">npm</option>
          </select>
        </div>
        <div><label title="Install, update, or uninstall a package.">Action</label>
          <select name="dep_action" id="dep-action">
            <option value="install">Install</option>
            <option value="update">Update</option>
            <option value="uninstall">Uninstall</option>
          </select>
        </div>
        <div><label title="Package name only (no extra flags).">Package</label><input name="dep_package" id="dep-package" value="" placeholder="colorama / lodash" title="Example: colorama (pip) or lodash (npm)." /></div>
        <div><label title="Exact version for manual mode.">Version (required for manual install/update)</label><input name="dep_version" id="dep-version" value="" placeholder="0.4.6 / 4.17.21" title="Use exact versions in manual mode." /></div>
        <div><label title="Manual requires exact version; Auto tries safe latest.">Mode</label>
          <select name="dep_mode" id="dep-mode">
            <option value="manual">Manual (exact version)</option>
            <option value="auto">Auto (safe latest via manager)</option>
          </select>
        </div>
        <div class="full actions">
          <label><input type="checkbox" name="dep_approved" id="dep-approved"> I understand the risk and approve this dependency change</label>
        </div>
        <div class="full hint">Safety: install/update runs a pre-check scan and blocks if CRITICAL findings are present. If package trust is uncertain, explicit approval is required.</div>
        <div class="full actions"><button type="submit" title="Execute dependency operation with SafeDeps checks.">Apply Dependency Action</button></div>
      </form>
      <details class="card" style="margin-top:12px;">
        <summary style="cursor:pointer; font-weight:700;">Test Dependency Guard (console)</summary>
        <div class="sub">Run controlled install/uninstall checks to quickly verify current scope enforcement.</div>
        <div class="section-loading-actions quick-actions" style="margin-top:12px;">
          <button type="button" onclick="runGuardProbe('pip', 'install', 'colorama', '0.4.6', 'manual')">Test pip install (pin)</button>
          <button type="button" class="danger" onclick="runGuardProbe('pip', 'uninstall', 'colorama', '', 'manual')">Test pip uninstall</button>
          <button type="button" onclick="runGuardProbe('npm', 'install', 'lodash', '4.17.21', 'manual')">Test npm install (pin)</button>
          <button type="button" class="danger" onclick="runGuardProbe('npm', 'uninstall', 'lodash', '', 'manual')">Test npm uninstall</button>
        </div>
      </details>
      </section>
      <section class="section page-section" id="section-deps-console" data-page="console">
        <div class="section-header">
          <div>
            <h2>Dependency Action Console</h2>
            <p class="sub">Captured dependency action output stays visible after each operation.</p>
          </div>
        </div>
        <p class="sub">This output is captured from the action command path and stays visible after each operation.</p>
        <pre id="dependency-console" class="console-output">{_html_escape(state.get('dependency_output', 'No dependency action executed yet.'))}</pre>
      </section>
      <section class="section page-section" data-page="exceptions">
      <details class="card" id="section-rule-help" open>
      <summary>Explain Scan Warnings/Errors <span class="adv-tag">(Advanced)</span></summary>
      <p class="sub">Use this when SafeDeps shows a warning/error code and you do not understand it. Enter the exact code from findings (example: `FLOATING_VERSION`, `UNPINNED_VERSION`, `MISSING_LOCKFILE`).</p>
      <form method="post" autocomplete="off" action="/explain" data-ajax="1" data-pending="section-rule-help">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label title="Code shown in SafeDeps findings table.">Warning/error code</label><input name="rule" value="{_html_escape(state['rule'])}" placeholder="FLOATING_VERSION" title="Enter the exact code you see in findings, for example UNPINNED_VERSION." /></div>
        <div class="actions"><button type="submit">Explain Rule</button></div>
      </form>
      </details>
      <details class="card" id="section-baseline" style="margin-top:14px;">
      <summary>Baseline And Exceptions <span class="adv-tag">(Advanced)</span></summary>
      <p class="sub">Use baseline only for controlled exceptions. Always set expiration dates.</p>
      <form method="post" autocomplete="off" action="/baseline" data-ajax="1" data-pending="section-baseline">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label title="Scan report JSON used to build baseline.">Report path</label><input name="report" value="{_html_escape(state['report'])}" title="Path to safedeps-report.json." /></div>
        <div><label>Baseline output path</label><input name="baseline_output" value="{_html_escape(state['baseline_output'])}" /></div>
        <div class="full actions"><button type="submit">Create Baseline</button></div>
      </form>
      <form method="post" autocomplete="off" action="/approve" id="approve-form" data-ajax="1" data-pending="section-baseline">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label>Baseline file</label><input id="approve-baseline-file" name="baseline_file" value="{_html_escape(state['baseline_file'])}" /></div>
        <div><label>Manager</label><input id="approve-manager" name="manager" value="{_html_escape(state['manager'])}" placeholder="npm / pip / nuget" /></div>
        <div><label>Rule</label><input id="approve-rule" name="approve_rule" value="{_html_escape(state['approve_rule'])}" placeholder="FLOATING_VERSION" /></div>
        <div><label>Package (optional)</label><input id="approve-package" name="package" value="{_html_escape(state['package'])}" placeholder="lodash" /></div>
        <div><label>File (optional)</label><input id="approve-file" name="file_value" value="{_html_escape(state['file_value'])}" placeholder="package.json" /></div>
        <div><label>Expires (YYYY-MM-DD)</label><input id="approve-expires" name="expires" value="{_html_escape(state['expires'])}" placeholder="2026-12-31" /></div>
        <div class="full actions"><button type="submit">Add/Update Approval</button></div>
        <div class="full hint">Tip: use "Use For Approval" on a finding row to prefill manager/rule/package/file.</div>
      </form>
      </details>
      </section>
      <section class="section page-section" id="section-policy" data-page="policy">
      <div class="section-header">
        <div>
          <h2>Policy Quick Editor</h2>
          <p class="sub">Custom hardening for registry trust and package deny rules.</p>
        </div>
      </div>
      <p class="sub">This section is for custom hardening. Most users can keep defaults and only use scan + guided dependency actions.</p>
      <div class="grid2">
        <form method="post" autocomplete="off" action="/policy" data-ajax="1" data-pending="section-policy">
          <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
          <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
          <input type="hidden" name="policy_action" value="add_registry" />
          <div><label>Policy file (optional)</label><input name="policy_path" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" /></div>
          <div><label>Manager</label><input name="policy_manager" value="" placeholder="npm / pip / nuget" /></div>
          <div class="full"><label>Registry URL to trust</label><input name="policy_registry" value="" placeholder="https://registry.npmjs.org/" /></div>
          <div class="full actions"><button type="submit">Add Registry To Allowlist</button></div>
        </form>
        <form method="post" autocomplete="off" action="/policy" data-ajax="1" data-pending="section-policy">
          <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
          <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
          <div><label>Policy action</label>
            <select name="policy_action">
              <option value="add_deny">Add deny package</option>
              <option value="remove_deny">Remove deny package</option>
            </select>
          </div>
          <div><label>Package name</label><input name="policy_package" value="" placeholder="example-package" /></div>
          <div class="full"><label>Policy file (optional)</label><input name="policy_path" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" /></div>
          <div class="full actions"><button type="submit">Apply Package Policy Action</button></div>
        </form>
      </div>
      </section>
      <section class="section page-section" id="section-intel" data-page="intel">
      <div class="section-header">
        <div>
          <h2>Intelligence Settings</h2>
          <p class="sub">Maintain local vulnerability feed and package metadata cache JSON.</p>
        </div>
      </div>
      <form method="post" autocomplete="off" action="/intelligence" data-ajax="1" data-pending="section-intel">
        <div class="full"><label>Intelligence Settings</label></div>
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div class="full"><label>Local vulnerability feed JSON (`.safedeps/vuln-feed.json`)</label><textarea name="vuln_feed_json">{_html_escape(state['vuln_feed_json'])}</textarea></div>
        <div class="full"><label>Local metadata cache JSON (`.safedeps/metadata-cache.json`)</label><textarea name="metadata_cache_json">{_html_escape(state['metadata_cache_json'])}</textarea></div>
        <div class="full actions">
          <button type="submit" name="intel_action" value="save">Save Intelligence Files</button>
          <button type="submit" name="intel_action" value="template">Create Starter Templates</button>
        </div>
        <div class="full hint">This lets users configure local intelligence visually instead of editing files manually.</div>
      </form>
      </section>
      </div>
    </main>
  </div>
  <div class="modal-backdrop" id="rule-modal-backdrop" aria-hidden="true">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="rule-modal-title">
      <div class="modal-head">
        <h3 class="modal-title" id="rule-modal-title">Rule Explanation</h3>
        <button type="button" class="modal-close" id="rule-modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-body" id="rule-modal-body"></div>
    </div>
  </div>
  <div class="modal-backdrop" id="project-path-modal-backdrop" aria-hidden="true">
    <div class="modal path-modal" role="dialog" aria-modal="true" aria-labelledby="project-path-modal-title">
      <div class="modal-head">
        <h3 class="modal-title" id="project-path-modal-title">Project Path</h3>
        <button type="button" class="modal-close" id="project-path-modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-body">
        <label class="modal-field-label" for="project-path-modal-input">Folder path</label>
        <input id="project-path-modal-input" class="modal-path-input" value="{_html_escape(state['path'])}" />
        <div class="path-modal-actions">
          <button type="button" id="project-path-use-current" class="ghost">Use Current</button>
          <button type="button" id="project-path-use-dot" class="ghost">Use .</button>
          <button type="button" id="project-path-apply">Apply Path</button>
          <button type="button" class="ghost" id="project-path-cancel">Cancel</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-backdrop" id="dep-approve-modal-backdrop" aria-hidden="true">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="dep-approve-modal-title">
      <div class="modal-head">
        <h3 class="modal-title" id="dep-approve-modal-title">Approval required for Safe Update</h3>
        <button type="button" class="modal-close" id="dep-approve-modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-body">
        <p id="dep-approve-modal-text">This action may require explicit approval.</p>
        <div class="actions" style="margin-top:10px;">
          <button type="button" id="dep-approve-confirm">Confirm update</button>
          <button type="button" class="ghost" id="dep-approve-cancel">Cancel</button>
        </div>
      </div>
    </div>
  </div>
  <script>
    function showPage(pageName, activeScrollTarget) {{
      let page = pageName || "overview";
      if (!document.querySelector(`.page-section[data-page="${{page}}"]`)) {{
        page = "overview";
      }}
      document.body.setAttribute("data-page", page);
      document.querySelectorAll(".page-section").forEach((section) => {{
        section.classList.toggle("active", section.getAttribute("data-page") === page);
      }});
      document.querySelectorAll(".nav-item[data-page-target]").forEach((item) => {{
        const itemPage = item.getAttribute("data-page-target");
        const itemScroll = item.getAttribute("data-scroll-target") || "";
        const defaultScroll = page === "scan" ? "section-scan" : "";
        const activeScroll = activeScrollTarget || defaultScroll;
        item.classList.toggle("active", itemPage === page && itemScroll === activeScroll);
      }});
      localStorage.setItem("safedeps-page", page);
    }}
    function activePage() {{
      return document.body.getAttribute("data-page") || localStorage.getItem("safedeps-page") || "overview";
    }}
    function wireAppChrome() {{
      const savedPage = localStorage.getItem("safedeps-page") || "overview";
      showPage(savedPage);
      const collapsed = localStorage.getItem("safedeps-sidebar") === "collapsed";
      document.body.classList.toggle("sidebar-collapsed", collapsed);
      const toggleSidebar = function() {{
        const next = !document.body.classList.contains("sidebar-collapsed");
        document.body.classList.toggle("sidebar-collapsed", next);
        document.body.classList.toggle("sidebar-expanded", !next);
        localStorage.setItem("safedeps-sidebar", next ? "collapsed" : "expanded");
      }};
      document.querySelectorAll("#sidebar-toggle, #sidebar-toggle-bottom").forEach((btn) => {{
        if (btn.dataset.bound === "1") return;
        btn.dataset.bound = "1";
        btn.addEventListener("click", toggleSidebar);
      }});
      document.querySelectorAll(".nav-item[data-page-target]").forEach((btn) => {{
        if (btn.dataset.bound === "1") return;
        btn.dataset.bound = "1";
        btn.addEventListener("click", function() {{
          const scrollTarget = btn.getAttribute("data-scroll-target");
          showPage(btn.getAttribute("data-page-target"), scrollTarget);
          if (scrollTarget) {{
            const target = document.getElementById(scrollTarget);
            if (target) target.scrollIntoView({{ behavior: "smooth", block: "start" }});
          }}
          document.body.classList.remove("sidebar-expanded");
        }});
      }});
    }}
    (function() {{
      wireAppChrome();
      const saved = localStorage.getItem("safedeps-theme");
      if (saved) document.body.setAttribute("data-theme", saved);
      const btn = document.getElementById("theme-toggle");
      if (btn) {{
        btn.addEventListener("click", function() {{
          const current = document.body.getAttribute("data-theme") === "dark" ? "dark" : "light";
          const next = current === "dark" ? "light" : "dark";
          document.body.setAttribute("data-theme", next);
          localStorage.setItem("safedeps-theme", next);
        }});
      }}
      const initialPath = document.getElementById("scan-path-input");
      if (initialPath) {{
        syncPathInputs(initialPath.value);
      }}

      document.addEventListener("submit", function(event) {{
        const form = event.target;
        if (!form || form.tagName !== "FORM") return;
        const activePathInput = document.getElementById("scan-path-input");
        if (!activePathInput) return;
        const activePath = activePathInput.value;
        if (!activePath) return;
        form.querySelectorAll('input[name="path"]').forEach((el) => {{
          el.value = activePath;
        }});
      }});
    }})();
    function syncPathInputs(nextValue) {{
      if (!nextValue) return;
      document.querySelectorAll('input[name="path"]').forEach((el) => {{
        el.value = nextValue;
      }});
      const scanInput = document.getElementById("scan-path-input");
      if (scanInput) scanInput.value = nextValue;
      const modalInput = document.getElementById("project-path-modal-input");
      if (modalInput) modalInput.value = nextValue;
    }}
    function wirePathInput() {{
      const scanInput = document.getElementById("scan-path-input");
      const browseBtn = document.getElementById("browse-project-root");
      const syncScanInput = function() {{
        if (scanInput) syncPathInputs(scanInput.value);
      }};
      if (scanInput) {{
        scanInput.addEventListener("change", syncScanInput);
        scanInput.addEventListener("input", syncScanInput);
        scanInput.addEventListener("blur", syncScanInput);
      }}
      if (scanInput) {{
        syncScanInput(scanInput.value);
      }}
      if (browseBtn && scanInput) {{
        if (browseBtn.dataset.bound === "1") return;
        browseBtn.dataset.bound = "1";
        browseBtn.addEventListener("click", function() {{
          openProjectPathModal();
        }});
      }}
    }}
    wirePathInput();
    function openProjectPathModal() {{
      const backdrop = document.getElementById("project-path-modal-backdrop");
      const input = document.getElementById("project-path-modal-input");
      const scanInput = document.getElementById("scan-path-input");
      if (!backdrop || !input) return;
      input.value = (scanInput && scanInput.value) || input.value || ".";
      backdrop.classList.add("open");
      backdrop.setAttribute("aria-hidden", "false");
      setTimeout(() => {{
        input.focus();
        input.select();
      }}, 0);
    }}
    function closeProjectPathModal() {{
      const backdrop = document.getElementById("project-path-modal-backdrop");
      if (!backdrop) return;
      backdrop.classList.remove("open");
      backdrop.setAttribute("aria-hidden", "true");
    }}
    function applyProjectPathModal(value) {{
      const input = document.getElementById("project-path-modal-input");
      const nextValue = String(value || (input && input.value) || "").trim();
      if (!nextValue) return;
      syncPathInputs(nextValue);
      closeProjectPathModal();
    }}
    function normalizeInstallVersionInput(value) {{
      return (value || "").trim();
    }}
    function runGuardProbe(manager, action, pkg, version, mode) {{
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      const ds = document.getElementById("dep-runtime-scope");
      const consoleSection = document.getElementById("section-deps-console");
      showPage("console");
      if (consoleSection) {{
        consoleSection.classList.add("active");
      }}
      if (m) m.value = manager || "pip";
      if (a) a.value = action || "install";
      if (p) p.value = pkg || "";
      if (v) v.value = normalizeInstallVersionInput(version) || "";
      if (md) md.value = mode || "manual";
      if (ap) ap.checked = false;
      if (ds) ds.value = "";
      const row = document.querySelector(`tr[data-manager="${{(manager || "pip").toLowerCase()}}"][data-package="${{(pkg || "").toLowerCase()}}"]`);
      submitFormAjax("deps-form", row, action === "uninstall");
    }}
    function setApprovalFields(manager, rule, pkg, filePath) {{
      const m = document.getElementById("approve-manager");
      const r = document.getElementById("approve-rule");
      const p = document.getElementById("approve-package");
      const f = document.getElementById("approve-file");
      if (m) m.value = manager || "";
      if (r) r.value = rule || "";
      if (p) p.value = pkg || "";
      if (f) f.value = filePath || "";
      const form = document.getElementById("approve-form");
      showPage("exceptions");
      if (form) form.scrollIntoView({{ behavior: "smooth", block: "center" }});
    }}
    function quickApprove(manager, rule, pkg, filePath) {{
      setApprovalFields(manager, rule, pkg, filePath);
      const exp = document.getElementById("approve-expires");
      if (exp && !exp.value) {{
        const dt = new Date();
        dt.setDate(dt.getDate() + 30);
        const yyyy = dt.getFullYear();
        const mm = String(dt.getMonth() + 1).padStart(2, "0");
        const dd = String(dt.getDate()).padStart(2, "0");
        exp.value = `${{yyyy}}-${{mm}}-${{dd}}`;
      }}
    }}
    function prepareDependencyAction(manager, action, pkg, version, mode) {{
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      if (m) m.value = manager || "pip";
      if (a) a.value = action || "install";
      if (p) p.value = pkg || "";
      if (v) v.value = version || "";
      if (md) md.value = mode || "manual";
      if (ap) ap.checked = false;
      const form = document.getElementById("deps-form");
      showPage("scan", "section-deps-manage");
      if (form) form.scrollIntoView({{ behavior: "smooth", block: "center" }});
    }}
    let depApprovalContext = null;
    function openDepApprovalModal(ctx) {{
      depApprovalContext = ctx;
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      const txt = document.getElementById("dep-approve-modal-text");
      if (txt) {{
        txt.textContent = "Safe Update checks package trust signals. If metadata is missing or risky, approval is required. Confirm only if you reviewed the package and accept the risk.";
      }}
      if (backdrop) {{
        backdrop.classList.add("open");
        backdrop.setAttribute("aria-hidden", "false");
      }}
    }}
    function closeDepApprovalModal() {{
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      if (!backdrop) return;
      backdrop.classList.remove("open");
      backdrop.setAttribute("aria-hidden", "true");
      depApprovalContext = null;
    }}
    async function confirmDepApprovalAndRun() {{
      if (!depApprovalContext) return;
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      if (m) m.value = depApprovalContext.manager || "pip";
      if (a) a.value = depApprovalContext.action || "update";
      if (p) p.value = depApprovalContext.pkg || "";
      if (v) v.value = "";
      if (md) md.value = depApprovalContext.mode || "auto";
      if (ap) ap.checked = true;
      const row = depApprovalContext.row || null;
      closeDepApprovalModal();
      await submitFormAjax("deps-form", row, false);
    }}
    function executeDependencyAction(manager, action, pkg, mode, depScope) {{
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      const ds = document.getElementById("dep-runtime-scope");
      if (m) m.value = manager || "pip";
      if (a) a.value = action || "update";
      if (p) p.value = pkg || "";
      if (v) v.value = "";
      if (md) md.value = mode || "auto";
      if (ap) ap.checked = false;
      if (ds) {{
        ds.value = depScope || "";
      }}
      const selectedScope = (depScope || "").toLowerCase();
      const scopedRow = document.querySelector(
        `tr[data-manager="${{manager.toLowerCase()}}"][data-package="${{pkg.toLowerCase()}}"][data-runtime-scope="${{selectedScope}}"]`
      ) || document.querySelector(
        `tr[data-manager="${{manager.toLowerCase()}}"][data-package="${{pkg.toLowerCase()}}"][data-scope="${{selectedScope}}"]`
      );
      const row = scopedRow || document.querySelector(`tr[data-manager="${{manager.toLowerCase()}}"][data-package="${{pkg.toLowerCase()}}"]`);
      if (action === "update" && (mode || "").toLowerCase() === "auto") {{
        openDepApprovalModal({{ manager, action, pkg, mode, row }});
        return;
      }}
      const ok = confirm(`Proceed with ${{action}} for ${{pkg}} using ${{manager}}?`);
      if (!ok) return;
      submitFormAjax("deps-form", row, action === "uninstall");
    }}
    function bindAjaxHandlers() {{
      document.querySelectorAll('form[data-ajax="1"], .hero form[method="post"]').forEach(form => {{
        if (form.dataset.ajaxBound === "1") return;
        form.dataset.ajaxBound = "1";
        form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(btn => {{
          btn.addEventListener("click", function() {{
            form.__lastSubmitter = btn;
          }});
        }});
        form.addEventListener("submit", function(ev) {{
          ev.preventDefault();
          const isScan = form.id === "scan-form";
          submitFormAjax(form, null, false, isScan, ev.submitter || form.__lastSubmitter || null).then(() => {{
            if (form.action && form.action.endsWith("/explain")) {{
              const st = document.getElementById("status-wrap");
              if (st) {{
                const txt = (st.textContent || "").trim();
                if (txt) openRuleModal(txt);
              }}
            }}
          }});
        }});
      }});
    }}
    function escapeHtml(s) {{
      return String(s || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }}
    function openRuleModal(messageText) {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      const body = document.getElementById("rule-modal-body");
      if (!backdrop || !body) return;
      let pretty = messageText || "";
      if (pretty.includes(":")) {{
        const idx = pretty.indexOf(":");
        const code = pretty.slice(0, idx).trim();
        const msg = pretty.slice(idx + 1).trim();
        let nextHtml = "<p>Pin exact versions and use a lockfile.</p>";
        if (code === "FLOATING_VERSION" || code === "UNPINNED_VERSION") {{
          nextHtml =
            "<ul>" +
            "<li>Use an exact version, not a range.</li>" +
            "<li>Example (pip): <span class='modal-code'>requests==2.32.3</span> (not <span class='modal-code'>requests>=2</span>).</li>" +
            "<li>Create/update a lockfile and commit it to Git.</li>" +
            "</ul>";
        }} else if (code === "MISSING_LOCKFILE") {{
          nextHtml =
            "<ul>" +
            "<li>pip/requirements: <span class='modal-code'>pip freeze > requirements.lock</span></li>" +
            "<li>poetry: <span class='modal-code'>poetry lock</span></li>" +
            "<li>npm: <span class='modal-code'>npm install</span> (creates <span class='modal-code'>package-lock.json</span>), then use <span class='modal-code'>npm ci</span></li>" +
            "<li>nuget: enable <span class='modal-code'>RestorePackagesWithLockFile</span> and commit <span class='modal-code'>packages.lock.json</span></li>" +
            "</ul>";
        }}
        body.innerHTML =
          `<h4>Rule</h4><p><strong>${{escapeHtml(code)}}</strong></p>` +
          `<h4>What this means</h4><p>${{escapeHtml(msg)}}</p>` +
          "<h4>Why this matters</h4><p>Without pinned versions/lockfiles, two developers may install different dependency trees and one may pull a risky version.</p>" +
          "<h4>What to do next</h4>" +
          nextHtml;
      }} else {{
        body.innerHTML = `<p>${{escapeHtml(pretty)}}</p>`;
      }}
      backdrop.classList.add("open");
      backdrop.setAttribute("aria-hidden", "false");
    }}
    function closeRuleModal() {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      if (!backdrop) return;
      backdrop.classList.remove("open");
      backdrop.setAttribute("aria-hidden", "true");
    }}
    (function wireRuleModal() {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      const closeBtn = document.getElementById("rule-modal-close");
      if (closeBtn) closeBtn.addEventListener("click", closeRuleModal);
      if (backdrop) {{
        backdrop.addEventListener("click", function(ev) {{
          if (ev.target === backdrop) closeRuleModal();
        }});
      }}
      document.addEventListener("keydown", function(ev) {{
        if (ev.key === "Escape") {{
          closeRuleModal();
          closeProjectPathModal();
        }}
      }});
    }})();
    (function wireProjectPathModal() {{
      const backdrop = document.getElementById("project-path-modal-backdrop");
      const input = document.getElementById("project-path-modal-input");
      const closeBtn = document.getElementById("project-path-modal-close");
      const cancelBtn = document.getElementById("project-path-cancel");
      const applyBtn = document.getElementById("project-path-apply");
      const useCurrentBtn = document.getElementById("project-path-use-current");
      const useDotBtn = document.getElementById("project-path-use-dot");
      const scanInput = document.getElementById("scan-path-input");
      if (closeBtn) closeBtn.addEventListener("click", closeProjectPathModal);
      if (cancelBtn) cancelBtn.addEventListener("click", closeProjectPathModal);
      if (applyBtn) applyBtn.addEventListener("click", function() {{ applyProjectPathModal(); }});
      if (useCurrentBtn) useCurrentBtn.addEventListener("click", function() {{
        if (input && scanInput) {{
          input.value = scanInput.value || ".";
          input.focus();
          input.select();
        }}
      }});
      if (useDotBtn) useDotBtn.addEventListener("click", function() {{
        if (input) input.value = ".";
        applyProjectPathModal(".");
      }});
      if (input) {{
        input.addEventListener("keydown", function(ev) {{
          if (ev.key === "Enter") applyProjectPathModal();
          if (ev.key === "Escape") closeProjectPathModal();
        }});
      }}
      if (backdrop) {{
        backdrop.addEventListener("click", function(ev) {{
          if (ev.target === backdrop) closeProjectPathModal();
        }});
      }}
    }})();
    (function wireDepApproveModal() {{
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      const closeBtn = document.getElementById("dep-approve-modal-close");
      const cancelBtn = document.getElementById("dep-approve-cancel");
      const confirmBtn = document.getElementById("dep-approve-confirm");
      if (closeBtn) closeBtn.addEventListener("click", closeDepApprovalModal);
      if (cancelBtn) cancelBtn.addEventListener("click", closeDepApprovalModal);
      if (confirmBtn) confirmBtn.addEventListener("click", confirmDepApprovalAndRun);
      if (backdrop) {{
        backdrop.addEventListener("click", function(ev) {{
          if (ev.target === backdrop) closeDepApprovalModal();
        }});
      }}
    }})();
    function parseAndSwapSections(htmlText) {{
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlText, "text/html");
      const prevRows = new Map();
      document.querySelectorAll("#deps-table-wrap tbody tr[data-manager][data-package]").forEach(tr => {{
        const scope = tr.dataset.runtimeScope || tr.dataset.scope || "";
        const k = `${{tr.dataset.manager}}|${{tr.dataset.package}}|${{scope}}`;
        prevRows.set(k, tr.getBoundingClientRect());
      }});
      const ids = [
        "hero-wrap", "section-scan", "section-deps-view", "section-deps-manage",
        "section-rule-help", "section-baseline", "section-policy", "section-intel",
        "section-deps-console",
        "deps-table-wrap", "status-wrap", "pip-guard-wrap", "findings-wrap",
        "setup-status-line", "autoguard-status-line", "shellguard-status-line"
      ];
      ids.forEach(id => {{
        const src = doc.getElementById(id);
        const dst = document.getElementById(id);
        if (src && dst) {{
          dst.innerHTML = src.innerHTML;
        }}
      }});
      const updatedScanPath = doc.getElementById("scan-path-input");
      if (updatedScanPath && updatedScanPath.value) {{
        syncPathInputs(updatedScanPath.value);
      }}
      const newRows = new Map();
      document.querySelectorAll("#deps-table-wrap tbody tr[data-manager][data-package]").forEach(tr => {{
        const scope = tr.dataset.runtimeScope || tr.dataset.scope || "";
        const k = `${{tr.dataset.manager}}|${{tr.dataset.package}}|${{scope}}`;
        newRows.set(k, tr);
      }});
      newRows.forEach((tr, k) => {{
        const prev = prevRows.get(k);
        if (!prev) return;
        const now = tr.getBoundingClientRect();
        const dy = prev.top - now.top;
        if (Math.abs(dy) > 0.5) {{
          tr.style.transform = "none";
        }}
      }});
      bindAjaxHandlers();
      wireAppChrome();
      wirePathInput();
      wireDependencyFilters();
      showPage(activePage());
    }}
    function wireDependencyFilters() {{
      document.querySelectorAll("input[data-dependency-filter]").forEach((input) => {{
        if (input.dataset.bound === "1") return;
        input.dataset.bound = "1";
        input.addEventListener("input", function() {{
          const shell = input.closest(".dependency-table-shell");
          if (!shell) return;
          const q = input.value.trim().toLowerCase();
          const rows = shell.querySelectorAll("tbody tr");
          let visible = 0;
          rows.forEach((row) => {{
            const matched = !q || (row.textContent || "").toLowerCase().includes(q);
            row.style.display = matched ? "" : "none";
            if (matched) visible += 1;
          }});
          const count = shell.querySelector("[data-filter-count]");
          if (count) count.textContent = q ? `${{visible}} / ${{rows.length}} shown` : `${{rows.length}} dependencies`;
        }});
        input.dispatchEvent(new Event("input"));
      }});
    }}
    async function submitFormAjax(formRef, rowEl, animateExit, fullTablePending, submitter) {{
      const form = typeof formRef === "string" ? document.getElementById(formRef) : formRef;
      if (!form) return;
      const btn = submitter || form.__lastSubmitter || form.querySelector('button[type="submit"], input[type="submit"]');
      const fd = new FormData(form);
      const scanPathInput = document.getElementById("scan-path-input");
      if (scanPathInput && scanPathInput.value) {{
        fd.set("path", scanPathInput.value);
        syncPathInputs(scanPathInput.value);
      }}
      if (btn && btn.name) {{
        fd.append(btn.name, btn.value || "");
      }}
      const pendingId = form.getAttribute("data-pending");
      const pendingEl = pendingId ? document.getElementById(pendingId) : null;
      const isGuardStatePending = pendingId === "hero-wrap";
      if (pendingEl) {{
        pendingEl.classList.add("section-loading");
        if (isGuardStatePending) {{
          pendingEl.classList.add("guard-state-loading");
          pendingEl.setAttribute("aria-busy", "true");
        }}
      }}
      if (btn) {{
        btn.classList.add("button-loading");
        btn.setAttribute("aria-busy", "true");
      }}
      form.querySelectorAll("button, input, select, textarea").forEach((el) => {{
        if (el.type === "hidden") return;
        el.dataset.wasDisabled = el.disabled ? "1" : "0";
        el.disabled = true;
      }});
      if (rowEl) rowEl.classList.add("row-pending");
      if (fullTablePending) {{
        document.querySelectorAll("#deps-table-wrap tbody tr").forEach(tr => tr.classList.add("row-pending"));
        const depsView = document.getElementById("section-deps-view");
        const depsManage = document.getElementById("section-deps-manage");
        if (depsView) depsView.classList.add("section-loading");
        if (depsManage) depsManage.classList.add("section-loading");
      }}
      try {{
        const body = new URLSearchParams(fd);
        const res = await fetch(form.action, {{
          method: "POST",
          headers: {{ "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" }},
          body
        }});
        const text = await res.text();
        if (rowEl && animateExit) {{
          rowEl.classList.remove("row-pending");
          rowEl.classList.add("row-exit");
          await new Promise(r => setTimeout(r, 280));
        }}
        parseAndSwapSections(text);
      }} finally {{
        if (pendingEl) {{
          pendingEl.classList.remove("section-loading");
          if (isGuardStatePending) {{
            pendingEl.classList.remove("guard-state-loading");
            pendingEl.removeAttribute("aria-busy");
          }}
        }}
        if (btn) {{
          btn.classList.remove("button-loading");
          btn.removeAttribute("aria-busy");
        }}
        form.querySelectorAll("button, input, select, textarea").forEach((el) => {{
          if (el.type === "hidden") return;
          el.disabled = el.dataset.wasDisabled === "1";
          delete el.dataset.wasDisabled;
        }});
        if (fullTablePending) {{
          document.querySelectorAll("#deps-table-wrap tbody tr").forEach(tr => tr.classList.remove("row-pending"));
          const depsView = document.getElementById("section-deps-view");
          const depsManage = document.getElementById("section-deps-manage");
          if (depsView) depsView.classList.remove("section-loading");
          if (depsManage) depsManage.classList.remove("section-loading");
        }}
      }}
    }}
    bindAjaxHandlers();
    wireDependencyFilters();
  </script>
</body>
</html>
"""
