from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import __version__
from . import dependency_actions as _dependency_actions_mod
from . import guard as _guard
from . import runtime as _runtime_mod
from . import ui_dependencies as _ui_dependencies_mod
from .constants import RULE_EXPLAINERS, SEVERITY_ORDER
from .cli_parser import build_parser
from .dependency_actions import (
    _format_command_output,
    _format_dependency_ui_error,
    _evaluate_dependency_risk,
    _get_installed_version,
    _get_pip_required_by,
    _is_exact_version,
    _is_valid_package_name,
    _post_change_compat_checks,
    _rollback_dependency_change,
    _run_cmd,
    _safe_auto_version_npm,
    _safe_auto_version_pip,
    apply_dependency_action,
    apply_policy_quick_update,
)
from .doctor import _python_env_warnings, cmd_doctor
from .exceptions import cmd_approve, cmd_baseline, cmd_explain, upsert_approval_entry, write_baseline_file
from .policy import DEFAULT_POLICY
from .reports import (
    _component_ref,
    _finding_fingerprint,
    _finding_fingerprint_from_dict,
    _html_escape,
    _js_escape,
    _purl_for,
    _sarif_level,
    _unique_components,
    apply_vulnerability_baseline,
    finding_fingerprint,
    print_summary,
    to_cyclonedx,
    to_html_report,
    to_sarif,
    to_spdx,
)
from .runtime import (
    InstallMode,
    _default_ui_workspace,
    _detect_project_runtime_python,
    _has_project_runtime_candidates,
    _install_mode,
    _installation_scope_label,
    _is_project_scoped_install,
    _iter_project_runtime_candidates,
    _looks_like_project_root,
    _normalize_project_path,
    _project_runtime_python,
    _python_from_virtual_env,
    _resolve_ui_start_path,
    _runtime_python_for_action,
    _runtime_python_for_project_scope,
    _runtime_python_for_system_scope,
)
from .scan import run_online_audits, run_scan_pipeline
from .ui_render import (
    _is_runtime_component,
    _render_dependency_rows_table,
    collect_runtime_components,
    render_dependency_table,
    render_findings_table,
    render_pip_guard_panel,
    render_ui_page,
)
from .ui_server import cmd_ui, cmd_ui_shortcut
from .ui_state import (
    _ui_state_from_form,
    create_intelligence_templates,
    default_ui_state,
    load_intelligence_into_state,
    save_intelligence_from_state,
)


_ORIGINAL_COLLECT_RUNTIME_COMPONENTS = _ui_dependencies_mod.collect_runtime_components


class InstallMode(_runtime_mod.InstallMode):
    def project_runtime_python(self) -> str | None:
        return _runtime_python_for_project_scope(self.root)

    def system_runtime_python(self) -> str:
        return _runtime_python_for_system_scope()


def _install_mode(root: Path, label: str | None = None) -> InstallMode:
    return InstallMode(root, label)


def _runtime_python_for_action(root: Path, *, action_scope: str | None = None) -> str:
    return _install_mode(root).runtime_python_for_action(action_scope)


def collect_runtime_components(
    root: Path,
    *,
    python_executable: str | None = None,
    runtime_scope: str = "runtime",
    fallback_to_process: bool = False,
    local_only: bool = False,
):
    _ui_dependencies_mod.subprocess = subprocess
    return _ORIGINAL_COLLECT_RUNTIME_COMPONENTS(
        root,
        python_executable=python_executable,
        runtime_scope=runtime_scope,
        fallback_to_process=fallback_to_process,
        local_only=local_only,
    )


_COMPAT_COLLECT_RUNTIME_COMPONENTS = collect_runtime_components


def render_dependency_table(
    result,
    fail_on: str,
    root: Path,
    protection_scope: str = "project",
    installation_scope: str | None = None,
):
    collector = globals().get("collect_runtime_components")
    _ui_dependencies_mod.collect_runtime_components = (
        collector if collector is not _COMPAT_COLLECT_RUNTIME_COMPONENTS else _ORIGINAL_COLLECT_RUNTIME_COMPONENTS
    )
    _ui_dependencies_mod._install_mode = _install_mode
    _ui_dependencies_mod._has_project_runtime_candidates = _has_project_runtime_candidates
    _ui_dependencies_mod.subprocess = subprocess
    return _ui_dependencies_mod.render_dependency_table(
        result,
        fail_on,
        root,
        protection_scope=protection_scope,
        installation_scope=installation_scope,
    )


def apply_dependency_action(
    root: Path,
    manager: str,
    action: str,
    package: str,
    version: str,
    mode: str,
    approved: bool,
    approval_note: str,
    action_scope: str | None = None,
):
    _dependency_actions_mod.run_scan_pipeline = run_scan_pipeline
    _dependency_actions_mod._run_cmd = _run_cmd
    _dependency_actions_mod._runtime_python_for_action = _runtime_python_for_action
    _dependency_actions_mod._runtime_python_for_system_scope = _runtime_python_for_system_scope
    return _dependency_actions_mod.apply_dependency_action(
        root=root,
        manager=manager,
        action=action,
        package=package,
        version=version,
        mode=mode,
        approved=approved,
        approval_note=approval_note,
        action_scope=action_scope,
    )


def cmd_init(args):
    root = Path(args.path).resolve()
    d = root / ".safedeps"
    d.mkdir(exist_ok=True)
    p = d / "policy.json"
    if not p.exists() or args.force:
        p.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
    print(f"SafeDeps policy written: {p}")
    return 0


def cmd_scan(args):
    result, outdir = run_scan_pipeline(
        root=Path(args.path).resolve(),
        policy_arg=args.policy,
        out=args.out,
        fail_on=args.fail_on,
        online_audit=args.online_audit,
        sarif=args.sarif,
        cyclonedx=args.cyclonedx,
        spdx=args.spdx,
        html=args.html,
    )
    print_summary(result, args.fail_on, outdir)
    return 0 if result.ok else 2


def cmd_help(args):
    print("SafeDeps Quick Help")
    print("")
    print("Open UI")
    print("- Fast start (recommended): safedeps ui")
    print("- Custom path:              safedeps ui <project_or_folder>")
    print("- Custom port:              safedeps ui --port 5200")
    print("- Disable browser auto-open: safedeps ui --no-open-browser")
    print("- Default workspace:        ~/.safedeps/workspace (auto-created)")
    print("- Windows desktop launcher: safedeps ui-shortcut")
    print("")
    print("Core Commands")
    print("- Scan:       safedeps scan . --fail-on HIGH")
    print("- Setup:      safedeps setup .")
    print("- Rule help:  safedeps explain FLOATING_VERSION")
    print("- Baseline:   safedeps baseline . --report security-artifacts/safedeps-report.json --output .safedeps/vuln-baseline.json")
    print("- Approval:   safedeps approve . --manager pip --rule UNPINNED_VERSION --package requests --expires 2026-12-31")
    print("")
    print("Guard Activation")
    print(r"- PowerShell: . .\.safedeps\activate.ps1")
    print("- bash/zsh:   source .safedeps/activate.sh")
    print("- Note: UI actions map to these command families (scan/setup/explain/baseline/approve/policy/deps).")
    print("")
    print("Expected Runtime Behavior")
    print("- Unpinned runtime installs (example: pip install colorama) are blocked.")
    print("- Pinned install example: pip install colorama==0.4.6")
    return 0


def cmd_version(args):
    print(__version__)
    return 0


def cmd_guard_cleanup(args):
    root = Path(args.path).resolve()
    try:
        _guard.cleanup_guard_install(
            root,
            remove_project_artifacts=bool(getattr(args, "remove_project_artifacts", False)),
            disable_auto_guard=True,
        )
    except Exception:
        pass
    return 0


def cmd_setup(args):
    return _guard.cmd_setup(args)


def get_setup_status(root: Path):
    return _guard.get_setup_status(root)


def _guard_state_file(root: Path):
    return _guard._guard_state_file(root)


def _powershell_profile_candidates():
    return _guard._powershell_profile_candidates()


def _guard_profile_snippet(root: Path):
    return _guard._guard_profile_snippet(root)


def _load_guard_state(root: Path):
    return _guard._load_guard_state(root)


def _write_guard_state(root: Path, state: dict):
    return _guard._write_guard_state(root, state)


def _is_auto_guard_enabled(root: Path):
    return _guard._is_auto_guard_enabled(root)


def _set_powershell_autoguard(root: Path, enable: bool):
    return _guard._set_powershell_autoguard(root, enable)


def apply_guard_toggle(root: Path, action: str, install_scope: str | None = None):
    return _guard.apply_guard_toggle(root, action, install_scope=install_scope)


def get_guard_mode_status(root: Path):
    return _guard.get_guard_mode_status(root)


def get_protection_scope(root: Path):
    return _guard.get_protection_scope(root)


def detect_official_repo_url(root: Path):
    return _guard.detect_official_repo_url(root)


def get_current_shell_guard_status(root: Path):
    return _guard.get_current_shell_guard_status(root)


def main(argv=None):
    parser = build_parser(
        version=__version__,
        severity_choices=SEVERITY_ORDER,
        handlers={
            "version": cmd_version,
            "help": cmd_help,
            "init": cmd_init,
            "scan": cmd_scan,
            "doctor": cmd_doctor,
            "explain": cmd_explain,
            "baseline": cmd_baseline,
            "approve": cmd_approve,
            "ui": cmd_ui,
            "ui-shortcut": cmd_ui_shortcut,
            "setup": cmd_setup,
            "guard-cleanup": cmd_guard_cleanup,
        },
    )
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
