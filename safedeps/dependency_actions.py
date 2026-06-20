from __future__ import annotations

import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import guard as _guard
from .policy import DEFAULT_POLICY, Policy
from .runtime import _runtime_python_for_action, _runtime_python_for_system_scope
from .scan import run_scan_pipeline
from .scanners.metadata_signals import MetadataSignals

get_protection_scope = _guard.get_protection_scope

def apply_policy_quick_update(root: Path, action: str, manager: str, package: str, registry: str, policy_path: str):
    action = (action or "").strip().lower()
    manager = (manager or "").strip().lower()
    package = (package or "").strip()
    registry = (registry or "").strip()

    if policy_path:
        p = Path(policy_path)
        policy_file = p if p.is_absolute() else (root / p)
    else:
        policy_file = root / ".safedeps" / "policy.json"

    policy_file.parent.mkdir(parents=True, exist_ok=True)
    if policy_file.exists():
        try:
            data = json.loads(policy_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid policy JSON: {e}") from e
    else:
        data = json.loads(json.dumps(DEFAULT_POLICY))

    if action == "add_registry":
        if not manager:
            raise ValueError("manager is required for add_registry")
        if not registry:
            raise ValueError("registry URL is required for add_registry")
        allowed = data.setdefault("allowed_registries", {})
        entries = allowed.setdefault(manager, [])
        if registry not in entries:
            entries.append(registry)
            msg = f"Added registry to allowlist: {manager} -> {registry}"
        else:
            msg = f"Registry already present: {manager} -> {registry}"
    elif action == "add_deny":
        if not package:
            raise ValueError("package is required for add_deny")
        deny = data.setdefault("deny_packages", [])
        if package not in deny:
            deny.append(package)
            msg = f"Added deny package: {package}"
        else:
            msg = f"Package already in denylist: {package}"
    elif action == "remove_deny":
        if not package:
            raise ValueError("package is required for remove_deny")
        deny = data.setdefault("deny_packages", [])
        new_deny = [x for x in deny if str(x).lower() != package.lower()]
        if len(new_deny) == len(deny):
            msg = f"Package not found in denylist: {package}"
        else:
            data["deny_packages"] = new_deny
            msg = f"Removed deny package: {package}"
    else:
        raise ValueError(f"Unknown policy action: {action}")

    policy_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return f"{msg} (saved to {policy_file})"

def _is_valid_package_name(name: str):
    if not name:
        return False
    for ch in name:
        if ch.isalnum() or ch in "._-@/":
            continue
        return False
    return True

def _is_exact_version(ver: str):
    if not ver:
        return False
    lower = ver.lower()
    return all(bad not in lower for bad in ("^", "~", "*", ">", "<", "=", "latest", "x"))

def _run_cmd(args: list[str], cwd: Path):
    proc = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    text = out if out else err
    return proc.returncode, text

def _format_command_output(args: list[str], result_code: int, text: str):
    cmd = " ".join(shlex.quote(a) for a in args)
    if text:
        return f"$ {cmd}\n{text}\nexit code: {result_code}"
    return f"$ {cmd}\n(exit code: {result_code})"

def _format_dependency_ui_error(raw: str):
    text = str(raw or "").strip()
    if text.startswith("Uninstall blocked:"):
        return text
    if "Explicit approval required before this dependency change." in text:
        return (
            "Update blocked for safety. We could not verify trusted metadata for this package yet. "
            "If you still want to continue, confirm approval from the Safe Update overlay or tick the approval checkbox in 'Manage Dependencies'. "
            "For long-term use, fill '.safedeps/metadata-cache.json' in Intelligence Settings."
        )
    if "Manual install/update requires an exact version" in text:
        return "Blocked: you must use an exact version (example: 1.2.3). Do not use ranges like >=, ^ or latest."
    if "Blocked by CRITICAL findings" in text:
        return "Blocked: there are CRITICAL findings in this project. Resolve those first, then retry this action."
    if "failed compatibility checks and was rolled back" in text:
        reason = ""
        if "Reason:" in text:
            reason = text.split("Reason:", 1)[1].strip()
        label = "Uninstall blocked" if " uninstall " in f" {text.lower()} " else "Update blocked"
        if reason:
            return (
                f"{label}: compatibility checks failed, so SafeDeps restored the previous version automatically. "
                f"Reason: {reason}"
            )
        return f"{label}: compatibility checks failed, so SafeDeps restored the previous version automatically."
    if "failed compatibility checks and rollback also failed" in text:
        reason = ""
        if "Reason:" in text:
            # Keep the first compatibility reason and include the rollback detail after it.
            reason = text.split("Reason:", 1)[1].strip()
        label = "Uninstall blocked" if " uninstall " in f" {text.lower()} " else "Update blocked"
        if reason:
            return (
                f"{label}: compatibility checks failed and rollback also failed. "
                f"Reason: {reason}"
            )
        return f"{label}: compatibility checks failed and rollback also failed."
    return text

def _safe_auto_version_pip(root: Path, package: str, runtime_python: str | None = None):
    runtime_python = runtime_python or _runtime_python_for_system_scope()
    code, text = _run_cmd([runtime_python, "-m", "pip", "index", "versions", package], root)
    if code != 0:
        raise ValueError(f"pip index versions failed for {package}: {text}")
    line = ""
    for ln in text.splitlines():
        if "Available versions:" in ln:
            line = ln
            break
    if not line:
        raise ValueError(f"Could not resolve available versions for {package}.")
    versions = [x.strip() for x in line.split(":", 1)[1].split(",") if x.strip()]
    if not versions:
        raise ValueError(f"No versions returned for {package}.")
    return versions[0]

def _safe_auto_version_npm(root: Path, package: str):
    code, text = _run_cmd(["npm", "view", package, "version", "--json"], root)
    if code != 0:
        raise ValueError(f"npm view failed for {package}: {text}")
    try:
        data = json.loads(text)
    except Exception:
        data = text.strip().strip('"')
    if isinstance(data, str) and data:
        return data
    raise ValueError(f"Could not resolve latest npm version for {package}.")

def _get_installed_version(root: Path, manager: str, package: str, runtime_python: str | None = None):
    if manager == "pip":
        runtime_python = runtime_python or _runtime_python_for_system_scope()
        code, text = _run_cmd([runtime_python, "-m", "pip", "show", package], root)
        if code != 0:
            return ""
        for ln in text.splitlines():
            if ln.lower().startswith("version:"):
                return ln.split(":", 1)[1].strip()
        return ""
    if manager == "npm":
        code, text = _run_cmd(["npm", "ls", package, "--depth=0", "--json"], root)
        if code != 0 and not text:
            return ""
        try:
            data = json.loads(text or "{}")
        except Exception:
            return ""
        deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
        meta = deps.get(package) if isinstance(deps, dict) else None
        if isinstance(meta, dict):
            return str(meta.get("version", "")).strip()
        return ""
    return ""

def _get_pip_required_by(root: Path, package: str, runtime_python: str | None = None):
    runtime_python = runtime_python or _runtime_python_for_system_scope()
    code, text = _run_cmd([runtime_python, "-m", "pip", "show", package], root)
    if code != 0:
        return []
    for ln in text.splitlines():
        if ln.lower().startswith("required-by:"):
            value = ln.split(":", 1)[1].strip()
            if not value:
                return []
            return sorted({item.strip() for item in value.split(",") if item.strip()})
    return []

def _post_change_compat_checks(root: Path, manager: str, runtime_python: str | None = None):
    checks = []
    if manager == "pip":
        runtime_python = runtime_python or _runtime_python_for_system_scope()
        checks.append(("pip check", [runtime_python, "-m", "pip", "check"]))
    elif manager == "npm":
        checks.append(("npm ls --depth=0", ["npm", "ls", "--depth=0"]))
    failures = []
    for label, cmd in checks:
        code, text = _run_cmd(cmd, root)
        if code != 0:
            failures.append(f"{label} failed: {text}")
    return failures

def _rollback_dependency_change(root: Path, manager: str, package: str, previous_version: str, runtime_python: str | None = None):
    runtime_python = runtime_python or _runtime_python_for_system_scope()
    if manager == "pip":
        if previous_version:
            code, text = _run_cmd([runtime_python, "-m", "pip", "install", f"{package}=={previous_version}"], root)
            return code == 0, text
        code, text = _run_cmd([runtime_python, "-m", "pip", "uninstall", "-y", package], root)
        return code == 0, text
    if manager == "npm":
        if previous_version:
            code, text = _run_cmd(["npm", "install", f"{package}@{previous_version}"], root)
            return code == 0, text
        code, text = _run_cmd(["npm", "uninstall", package], root)
        return code == 0, text
    return False, "Unsupported manager for rollback."

def _evaluate_dependency_risk(root: Path, manager: str, package: str, resolved_version: str, mode: str):
    policy = Policy.load(root, None)
    warnings = []
    if policy.is_denied(package):
        raise ValueError(f"Package '{package}' is denylisted by policy.")

    signals = MetadataSignals.load(root)
    meta = signals.get(manager, package)
    published = str(meta.get("published", "")).strip()
    if not published:
        warnings.append("No trusted package metadata found in local intelligence cache.")
    else:
        try:
            age_days = (datetime.now(timezone.utc).date() - datetime.fromisoformat(published).date()).days
            if age_days < 2:
                warnings.append(f"Package is very new ({age_days} day old).")
            elif age_days < 7:
                warnings.append(f"Package is recent ({age_days} days old).")
        except Exception:
            warnings.append("Package publish date is invalid/unreadable in metadata cache.")
    if mode == "auto" and not resolved_version:
        warnings.append("Auto mode could not determine a pinned version.")
    return warnings

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
    if manager not in ("pip", "npm"):
        raise ValueError("Manager must be pip or npm.")
    if action not in ("install", "update", "uninstall"):
        raise ValueError("Action must be install, update, or uninstall.")
    if not _is_valid_package_name(package):
        raise ValueError("Invalid package name.")
    mode = mode if mode in ("manual", "auto") else "manual"

    # Always pre-check critical findings before mutating dependencies.
    pre, _ = run_scan_pipeline(
        root=root,
        policy_arg=None,
        out="security-artifacts",
        fail_on="CRITICAL",
        online_audit=False,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )
    if not pre.ok:
        raise ValueError("Blocked by CRITICAL findings. Resolve blockers before dependency changes.")

    resolved_version = version.strip()
    runtime_python = _runtime_python_for_action(root, action_scope=action_scope)
    if action in ("install", "update"):
        if mode == "manual":
            if not _is_exact_version(resolved_version):
                raise ValueError("Manual install/update requires an exact version (example: 1.2.3).")
        else:
            if manager == "pip":
                resolved_version = _safe_auto_version_pip(
                    root,
                    package,
                    runtime_python=runtime_python,
                )
            else:
                resolved_version = _safe_auto_version_npm(root, package)

        risk_warnings = _evaluate_dependency_risk(root, manager, package, resolved_version, mode)
        if risk_warnings and not approved:
            joined = "; ".join(risk_warnings)
            raise ValueError(
                "Explicit approval required before this dependency change. "
                f"Risk notes: {joined}. Tick the approval checkbox and add a reason."
            )

    previous_version = _get_installed_version(
        root,
        manager,
        package,
        runtime_python=runtime_python,
    )
    if manager == "pip" and action == "uninstall":
        required_by = _get_pip_required_by(root, package, runtime_python=runtime_python)
        if required_by:
            deps = ", ".join(required_by)
            raise ValueError(
                f"Uninstall blocked: {package} is required by installed package(s): {deps}. "
                "Uninstall or update those packages first, then retry."
            )

    if manager == "pip":
        if action == "install":
            cmd = [runtime_python, "-m", "pip", "install", f"{package}=={resolved_version}"]
        elif action == "update":
            cmd = [runtime_python, "-m", "pip", "install", "--upgrade", f"{package}=={resolved_version}"]
        else:
            cmd = [runtime_python, "-m", "pip", "uninstall", "-y", package]
    else:
        if action == "install" or action == "update":
            cmd = ["npm", "install", f"{package}@{resolved_version}"]
        else:
            cmd = ["npm", "uninstall", package]

    logs = []
    code, text = _run_cmd(cmd, root)
    logs.append(_format_command_output(cmd, code, text))
    if action == "uninstall" and code == 0:
        normalized_output = (text or "").lower()
        if "skipping" in normalized_output and "as it is not installed" in normalized_output:
            target_scope = action_scope or get_protection_scope(root)
            raise ValueError(
                f"{package} is not installed in the selected {target_scope} runtime scope. "
                f"Command used: {cmd[0]}"
            )
    if code != 0:
        raise ValueError(f"{manager} {action} failed:\n{_format_command_output(cmd, code, text)}")

    compat_failures = _post_change_compat_checks(root, manager, runtime_python=runtime_python)
    if compat_failures:
        rollback_cmd = []
        if manager == "pip":
            if previous_version:
                rollback_cmd = [runtime_python, "-m", "pip", "install", f"{package}=={previous_version}"]
            else:
                rollback_cmd = [runtime_python, "-m", "pip", "uninstall", "-y", package]
        elif manager == "npm":
            if previous_version:
                rollback_cmd = ["npm", "install", f"{package}@{previous_version}"]
            else:
                rollback_cmd = ["npm", "uninstall", package]
        ok_rb, rb_text = _rollback_dependency_change(
            root,
            manager,
            package,
            previous_version,
            runtime_python=runtime_python,
        )
        if rb_text:
            logs.append(_format_command_output(rollback_cmd, 0 if ok_rb else 1, rb_text))
        if ok_rb:
            raise ValueError(
                f"{manager} {action} failed compatibility checks and was rolled back. "
                f"Reason: {' | '.join(compat_failures)}"
            )
        raise ValueError(
            f"{manager} {action} failed compatibility checks and rollback also failed. "
            f"Reason: {' | '.join(compat_failures)} | rollback: {rb_text}"
        )

    post, _ = run_scan_pipeline(
        root=root,
        policy_arg=None,
        out="security-artifacts",
        fail_on="CRITICAL",
        online_audit=False,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )
    if not post.ok:
        raise ValueError(f"{manager} {action} applied, but post-check found CRITICAL issues. Review findings in UI.")

    if manager == "pip" and resolved_version:
        logs.append(_format_command_output([runtime_python, "-m", "pip", "show", package], 0, ""))
    if manager == "npm" and resolved_version:
        logs.append(_format_command_output(["npm", "ls", package, "--depth=0", "--json"], 0, ""))
    ver_text = f" @{resolved_version}" if resolved_version else ""
    approved_msg = ""
    if action in ("install", "update") and approved:
        approved_msg = " Explicit approval confirmed."
    logs.append("post-change guard checks passed.")
    return (
        f"{manager} {action} completed for {package}{ver_text}. "
        f"Pre/post CRITICAL checks passed and compatibility checks passed.{approved_msg}"
    ), "\n\n".join(logs)
