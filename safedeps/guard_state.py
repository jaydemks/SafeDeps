from __future__ import annotations

import json
import os
import re
import shutil
import sys
from contextlib import suppress
from pathlib import Path

from .guard_hooks import remove_interpreter_guard_hook


def get_setup_status(root: Path):
    pip_wrapper = root / ".safedeps" / "bin" / "pip.cmd" if _is_windows() else root / ".safedeps" / "bin" / "pip"
    activate = root / ".safedeps" / "activate.sh"
    activate_bat = root / ".safedeps" / "activate.bat"
    activate_ps1 = root / ".safedeps" / "activate.ps1"
    policy = root / ".safedeps" / "policy.json"
    missing = []
    if not policy.exists():
        missing.append("policy")
    if not pip_wrapper.exists():
        missing.append("pip wrapper")
    if not activate.exists():
        missing.append("activate script")
    if not activate_bat.exists():
        missing.append("CMD activate script")
    if not activate_ps1.exists():
        missing.append("PowerShell activate script")
    if missing:
        return f"Not configured ({', '.join(missing)} missing). Run: safedeps setup ."
    return "Configured. Activate with: source .safedeps/activate.sh (bash), .safedeps\\activate.bat (CMD), or . .safedeps/activate.ps1 (PowerShell)"

def cleanup_guard_install(root: Path, remove_project_artifacts: bool = False, disable_auto_guard: bool = True):
    root = Path(root).resolve()
    state = _load_guard_state(root)
    previous_auto_guard = _state_auto_guard_enabled(state)
    if disable_auto_guard:
        state["auto_guard"] = False
        state["auto_guard_powershell"] = False
    _write_guard_state(root, state)
    _set_user_path_guard_entry(root, False)
    _set_powershell_autoguard(root, False)
    _set_cmd_autorun_autoguard(root, False)
    remove_interpreter_guard_hook()
    if not disable_auto_guard:
        state = _load_guard_state(root)
        state["auto_guard"] = previous_auto_guard
        state["auto_guard_powershell"] = previous_auto_guard
        _write_guard_state(root, state)

    for name in ("pip", "pip3", "python", "python3", "npm"):
        os.environ.pop(name, None)

    if remove_project_artifacts:
        for rel in (".safedeps/bin", ".safedeps/bin-posix"):
            target = root / rel
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
        for rel in (".safedeps/activate.sh", ".safedeps/activate.bat", ".safedeps/activate.ps1"):
            target = root / rel
            try:
                if target.exists():
                    target.unlink()
            except Exception:
                pass
    return 0

def _guard_state_file(root: Path):
    return root / ".safedeps" / "guard-state.json"

def _powershell_profile_candidates():
    home = Path.home()
    return [
        home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
        home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
    ]

def _running_in_virtualenv_for_safedeps():
    # Treat SafeDeps as virtualenv-installed when invoked from a non-base interpreter.
    # This makes UI and scope decisions consistent when safedeps is launched from a project venv.
    return getattr(sys, "base_prefix", sys.prefix) != sys.prefix

def _is_project_install_scope(install_scope: str | None = None):
    scope = str(install_scope or "").strip().lower()
    if scope in ("project", "venv"):
        return True
    if scope in ("system", "global"):
        return False
    return _running_in_virtualenv_for_safedeps()

def _is_windows():
    return os.name == "nt"

def _get_user_path_entries_windows():
    if not _is_windows():
        return []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
            raw, _ = winreg.QueryValueEx(key, "Path")
            return [p for p in str(raw).split(";") if p] if raw else []
    except Exception:
        return []

def _write_user_path_entries_windows(entries: list[str]):
    if not _is_windows():
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(entries))
        return True
    except Exception:
        return False

def _get_cmd_autorun_windows():
    if not _is_windows():
        return ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor", 0, winreg.KEY_READ) as key:
            raw, _ = winreg.QueryValueEx(key, "AutoRun")
            return str(raw or "")
    except Exception:
        return ""

def _write_cmd_autorun_windows(value: str):
    if not _is_windows():
        return False
    try:
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor", 0, winreg.KEY_SET_VALUE) as key:
            if value.strip():
                winreg.SetValueEx(key, "AutoRun", 0, winreg.REG_EXPAND_SZ, value)
            else:
                with suppress(FileNotFoundError):
                    winreg.DeleteValue(key, "AutoRun")
        return True
    except Exception:
        return False

def _is_safedeps_bindir_entry(path_entry: str):
    normalized = re.sub(r"/+", "/", str(path_entry).strip().replace("\\", "/").lower())
    return ".safedeps/bin" in normalized

def _filter_guard_path_entries(entries: list[str], keep_guard_bin: str | None):
    keep_norm = re.sub(r"/+", "/", str(keep_guard_bin).strip().lower().replace("\\", "/")) if keep_guard_bin else None
    filtered = []
    seen = set()
    for raw in entries:
        raw_str = str(raw).strip()
        if not raw_str:
            continue
        raw_norm = re.sub(r"/+", "/", raw_str.lower().replace("\\", "/"))
        if _is_safedeps_bindir_entry(raw_str):
            if keep_norm and raw_norm == keep_norm:
                if raw_norm in seen:
                    continue
                filtered.append(raw_str)
                seen.add(raw_norm)
            continue
        if raw_norm in seen:
            continue
        filtered.append(raw_str)
        seen.add(raw_norm)
    return filtered

def _set_user_path_guard_entry(root: Path, enable: bool):
    guard_bin = str((root / ".safedeps" / "bin").resolve())
    norm_guard = guard_bin.lower().replace("\\", "/")
    if _is_windows():
        entries = _get_user_path_entries_windows()
        filtered = _filter_guard_path_entries(entries, guard_bin if enable else None)
        if enable:
            existing = {str(e).strip().lower().replace("\\", "/") for e in filtered}
            if norm_guard not in existing:
                filtered.insert(0, guard_bin)
        ok = _write_user_path_entries_windows(filtered)
    else:
        ok = True
    cur_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    cur_filtered = _filter_guard_path_entries(cur_entries, guard_bin if enable else None)
    if enable:
        existing = {str(e).strip().lower().replace("\\", "/") for e in cur_filtered}
        if norm_guard not in existing:
            cur_filtered.insert(0, guard_bin)
    os.environ["PATH"] = os.pathsep.join(cur_filtered)
    return ok

def _guard_profile_snippet(root: Path):
    activate_ps1 = (root / ".safedeps" / "activate.ps1").resolve()
    return (
        "# >>> SafeDeps Auto Guard >>>\n"
        f'if (Test-Path "{activate_ps1}") {{ . "{activate_ps1}" }}\n'
        "# <<< SafeDeps Auto Guard <<<\n"
    )

def _cmd_autorun_snippet(root: Path):
    activate_bat = str((root / ".safedeps" / "activate.bat").resolve()).replace('"', "")
    return f'if "SafeDeps Auto Guard"=="SafeDeps Auto Guard" if exist "{activate_bat}" call "{activate_bat}"'

def _strip_autoguard_blocks(text: str):
    marker_start = "# >>> SafeDeps Auto Guard >>>"
    marker_end = "# <<< SafeDeps Auto Guard <<<"
    pattern = re.compile(re.escape(marker_start) + r".*?" + re.escape(marker_end) + r"\r?\n?", re.IGNORECASE | re.DOTALL)
    return re.sub(pattern, "", text)

def _strip_cmd_autorun_blocks(text: str):
    old_marker_start = "rem >>> SafeDeps Auto Guard >>>"
    old_marker_end = "rem <<< SafeDeps Auto Guard <<<"
    old_pattern = re.compile(
        r"(\s*&\s*)?"
        + re.escape(old_marker_start)
        + r".*?"
        + re.escape(old_marker_end)
        + r"(\s*&\s*)?",
        re.IGNORECASE | re.DOTALL,
    )
    new_pattern = re.compile(
        r'(\s*&\s*)?if\s+"SafeDeps Auto Guard"=="SafeDeps Auto Guard"\s+if\s+exist\s+".*?\.safedeps[\\/]activate\.bat"\s+call\s+".*?\.safedeps[\\/]activate\.bat"(\s*&\s*)?',
        re.IGNORECASE,
    )
    cleaned = re.sub(old_pattern, " & ", text or "")
    cleaned = re.sub(new_pattern, " & ", cleaned)
    cleaned = re.sub(r"(\s*&\s*){2,}", " & ", cleaned).strip()
    return re.sub(r"^&\s*|\s*&$", "", cleaned).strip()

def _load_guard_state(root: Path):
    default = {"auto_guard": False, "auto_guard_powershell": False, "protection_scope": "project", "project_root": str(root)}
    path = _guard_state_file(root)
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default
    except Exception:
        return default
    out = dict(default)
    out.update(data)
    if "auto_guard" not in data and "auto_guard_powershell" in data:
        out["auto_guard"] = bool(data.get("auto_guard_powershell", False))
    if "auto_guard_powershell" not in data and "auto_guard" in data:
        out["auto_guard_powershell"] = bool(data.get("auto_guard", False))
    return out

def _state_auto_guard_enabled(state: dict):
    return bool(state.get("auto_guard", state.get("auto_guard_powershell", False)))

def _write_guard_state(root: Path, state: dict):
    path = _guard_state_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")

def _is_auto_guard_enabled(root: Path):
    return _sync_autoguard_state_file(root)

def _set_powershell_autoguard(root: Path, enable: bool):
    snippet = _guard_profile_snippet(root)
    updated_any = False
    candidates = _powershell_profile_candidates()
    for profile in candidates:
        try:
            profile.parent.mkdir(parents=True, exist_ok=True)
            content = profile.read_text(encoding="utf-8") if profile.exists() else ""
        except OSError:
            continue
        cleaned = _strip_autoguard_blocks(content)
        if enable:
            updated = cleaned
            if updated and not updated.endswith("\n"):
                updated += "\n"
            updated += snippet
            if updated != content:
                try:
                    profile.write_text(updated, encoding="utf-8")
                    updated_any = True
                except OSError:
                    continue
        else:
            updated = cleaned
            if updated != content:
                try:
                    profile.write_text(updated, encoding="utf-8")
                    updated_any = True
                except OSError:
                    continue
    state = _load_guard_state(root)
    state["auto_guard"] = enable
    state["auto_guard_powershell"] = enable
    _write_guard_state(root, state)
    _set_user_path_guard_entry(root, enable)
    cmd_updated = _set_cmd_autorun_autoguard(root, enable)
    updated_any = updated_any or cmd_updated
    if enable and not updated_any:
        return "Auto guard already enabled for new PowerShell and CMD sessions."
    if (not enable) and not updated_any:
        return "Auto guard already disabled for new PowerShell and CMD sessions."
    return "Auto guard enabled for new PowerShell and CMD sessions." if enable else "Auto guard disabled for new PowerShell and CMD sessions."

def _set_cmd_autorun_autoguard(root: Path, enable: bool):
    if not _is_windows():
        return False
    current = _get_cmd_autorun_windows()
    cleaned = _strip_cmd_autorun_blocks(current)
    if enable:
        snippet = _cmd_autorun_snippet(root)
        updated = cleaned
        if updated:
            updated += " & "
        updated += snippet
    else:
        updated = cleaned
    if updated == current:
        return False
    return _write_cmd_autorun_windows(updated)

def _profile_snippet_present(root: Path):
    marker_start = "# >>> SafeDeps Auto Guard >>>"
    marker_end = "# <<< SafeDeps Auto Guard <<<"
    expected = _guard_profile_snippet(root)
    for profile in _powershell_profile_candidates():
        if not profile.exists():
            continue
        try:
            content = profile.read_text(encoding="utf-8")
        except Exception:
            continue
        if marker_start in content and marker_end in content and expected in content:
            return True
    return False

def _cmd_autorun_snippet_present(root: Path):
    if not _is_windows():
        return False
    current = _get_cmd_autorun_windows()
    expected = _cmd_autorun_snippet(root)
    return expected in current and "SafeDeps Auto Guard" in current

def _path_guard_entry_present(root: Path):
    guard_bin = str((root / ".safedeps" / "bin").resolve()).lower().replace("\\", "/")
    if _is_windows():
        return any(
            str(e).strip().lower().replace("\\", "/") == guard_bin
            for e in _get_user_path_entries_windows()
        )
    return any(
        str(e).strip().lower().replace("\\", "/") == guard_bin
        for e in os.environ.get("PATH", "").split(os.pathsep)
        if e
    )

def _effective_autoguard_enabled(root: Path):
    return _profile_snippet_present(root) or _cmd_autorun_snippet_present(root) or _path_guard_entry_present(root)

def _sync_autoguard_state_file(root: Path):
    effective = _effective_autoguard_enabled(root)
    state = _load_guard_state(root)
    if _state_auto_guard_enabled(state) != effective or bool(state.get("auto_guard_powershell", False)) != effective:
        state["auto_guard"] = effective
        state["auto_guard_powershell"] = effective
        _write_guard_state(root, state)
    return effective

def _verify_autoguard_state(root: Path, expected_enabled: bool):
    state_enabled = _state_auto_guard_enabled(_load_guard_state(root))
    snippet_present = _profile_snippet_present(root)
    cmd_present = _cmd_autorun_snippet_present(root)
    path_present = _path_guard_entry_present(root)
    if expected_enabled:
        return state_enabled and (snippet_present or cmd_present or path_present)
    return (not state_enabled) and (not snippet_present) and (not cmd_present) and (not path_present)

def apply_guard_toggle(root: Path, action: str, install_scope: str | None = None):
    if action == "enable_auto":
        return _set_powershell_autoguard(root, True)
    if action == "disable_auto":
        return _set_powershell_autoguard(root, False)
    if action == "set_scope_project":
        state = _load_guard_state(root)
        state["protection_scope"] = "project"
        state["project_root"] = str(root)
        _write_guard_state(root, state)
        return "Protection scope set to PROJECT ONLY (inside this project path)."
    if action == "set_scope_global":
        if _is_project_install_scope(install_scope):
            state = _load_guard_state(root)
            state["protection_scope"] = "project"
            state["project_root"] = str(root)
            _write_guard_state(root, state)
            return (
                "Global scope is not available for SafeDeps venv installs. "
                "Scope forced to PROJECT to avoid affecting system-wide Python contexts."
            )
        state = _load_guard_state(root)
        state["protection_scope"] = "global"
        state["project_root"] = str(root)
        _write_guard_state(root, state)
        return "Protection scope set to GLOBAL (inside and outside project path)."
    raise ValueError(f"Unknown guard action: {action}")

def _force_autoguard_resync(root: Path, target_enabled: bool):
    if target_enabled:
        _set_powershell_autoguard(root, False)
        if not _verify_autoguard_state(root, False):
            _set_powershell_autoguard(root, False)
        _set_powershell_autoguard(root, True)
        if not _verify_autoguard_state(root, True):
            _set_powershell_autoguard(root, True)
    else:
        _set_powershell_autoguard(root, True)
        if not _verify_autoguard_state(root, True):
            _set_powershell_autoguard(root, True)
        _set_powershell_autoguard(root, False)
        if not _verify_autoguard_state(root, False):
            _set_powershell_autoguard(root, False)

def get_guard_mode_status(root: Path):
    enabled = _is_auto_guard_enabled(root)
    scope = str(_load_guard_state(root).get("protection_scope", "project")).upper()
    shell_active = "ACTIVE" in get_current_shell_guard_status(root).upper()
    if shell_active and enabled:
        return f"ON now + auto-start ON | Scope: {scope}."
    if shell_active and not enabled:
        return f"ON in this session (manual) | Auto-start OFF | Scope: {scope}."
    if enabled:
        return f"Auto-start ON for new PowerShell/CMD sessions | Scope: {scope}."
    return f"OFF now (unless manually activated) | Auto-start OFF | Scope: {scope}."

def get_protection_scope(root: Path):
    scope = str(_load_guard_state(root).get("protection_scope", "project")).strip().lower()
    if scope not in ("project", "global"):
        return "project"
    return scope

def get_current_shell_guard_status(root: Path):
    bindir = str((root / ".safedeps" / "bin").resolve())
    path_value = os.environ.get("PATH", "")
    entries = path_value.split(os.pathsep)
    normalized = [str(Path(p).resolve()) if p else "" for p in entries]
    if bindir in normalized:
        return "ACTIVE (wrapper path present)."
    return "INACTIVE (wrapper path not found in current PATH)."
