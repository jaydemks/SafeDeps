from __future__ import annotations

import os
import sys
from pathlib import Path

from .guard_backend import GuardBackendFiles, write_guard_backend_files
from .guard_hooks import (
    _init_project,
    _runtime_guard_pth_line,
    _runtime_guard_pth_name,
    _runtime_guard_pth_names,
    _site_package_candidates,
    install_interpreter_guard_hook,
    remove_interpreter_guard_hook,
)
from .guard_repo import detect_official_repo_url
from .guard_state import (
    _cmd_autorun_snippet,
    _cmd_autorun_snippet_present,
    _effective_autoguard_enabled,
    _filter_guard_path_entries,
    _force_autoguard_resync,
    _get_cmd_autorun_windows,
    _get_user_path_entries_windows,
    _guard_profile_snippet,
    _guard_state_file,
    _is_auto_guard_enabled,
    _is_project_install_scope,
    _is_safedeps_bindir_entry,
    _is_windows,
    _load_guard_state,
    _path_guard_entry_present,
    _powershell_profile_candidates,
    _profile_snippet_present,
    _running_in_virtualenv_for_safedeps,
    _set_cmd_autorun_autoguard,
    _set_powershell_autoguard,
    _set_user_path_guard_entry,
    _state_auto_guard_enabled,
    _strip_autoguard_blocks,
    _strip_cmd_autorun_blocks,
    _sync_autoguard_state_file,
    _verify_autoguard_state,
    _write_cmd_autorun_windows,
    _write_guard_state,
    _write_user_path_entries_windows,
    apply_guard_toggle,
    cleanup_guard_install,
    get_current_shell_guard_status,
    get_guard_mode_status,
    get_protection_scope,
    get_setup_status,
)


def cmd_setup(args):
    root = Path(args.path).resolve()
    fail_on = str(getattr(args, "fail_on", "HIGH") or "HIGH").upper()
    real_python = os.path.abspath(sys.executable)
    official_repo = detect_official_repo_url(root)
    install_scope = getattr(args, "install_scope", None)
    requested_protection_scope = str(getattr(args, "protection_scope", "auto") or "auto").strip().lower()
    project_install = _is_project_install_scope(install_scope)
    default_scope = "project" if project_install else "global"
    root_posix = str(root).replace("\\", "/")
    guard_state_posix = str(root / ".safedeps" / "guard-state.json").replace("\\", "/")
    expected_venv = str(Path(sys.prefix).resolve()) if project_install else ""
    expected_venv_posix = expected_venv.replace("\\", "/")
    _init_project(root, args.force)
    previous_state = _load_guard_state(root)
    previous_auto_guard = _state_auto_guard_enabled(previous_state)
    try:
        cleanup_guard_install(root, remove_project_artifacts=False, disable_auto_guard=False)
    except Exception:
        pass
    bindir = root / ".safedeps" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    posix_bindir = root / ".safedeps" / "bin-posix" if _is_windows() else bindir
    posix_bindir.mkdir(parents=True, exist_ok=True)
    if _is_windows():
        for stale_name in ("pip", "pip3", "python", "python3", "npm"):
            try:
                stale = bindir / stale_name
                if stale.exists() and stale.is_file():
                    stale.unlink()
            except Exception:
                pass

    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail

REAL_PY="{real_python}"
OFFICIAL_SAFEDEPS_GIT="{official_repo}"
PROJECT_ROOT="{root_posix}"
GUARD_STATE_FILE="{guard_state_posix}"
EXPECTED_VENV="{expected_venv_posix}"

resolve_project_root_from_state() {{
  local project_root="$PROJECT_ROOT"
  if [ -f "$GUARD_STATE_FILE" ]; then
    local state_root
    state_root="$(sed -n 's/.*"project_root"[[:space:]]*:[[:space:]]*"\\(.*\\)".*/\\1/p' "$GUARD_STATE_FILE" | head -n 1)"
    if [ -n "$state_root" ]; then
      project_root="$state_root"
    fi
  fi
  printf "%s" "$project_root"
}}

if ! "${{REAL_PY}}" -c "import safedeps" >/dev/null 2>&1; then
  exec "${{REAL_PY}}" -m pip "$@"
fi

if [ "${{1:-}}" = "install" ] || [ "${{1:-}}" = "uninstall" ] || [ "${{1:-}}" = "download" ]; then
  scope="project"
  if [ -f "$GUARD_STATE_FILE" ] && grep -q '"protection_scope"[[:space:]]*:[[:space:]]*"global"' "$GUARD_STATE_FILE"; then
    scope="global"
  fi
  ACTIVE_PROJECT_ROOT="$(resolve_project_root_from_state)"
  in_project=0
  case "${{PWD}}/" in
    "${{ACTIVE_PROJECT_ROOT}}"/*) in_project=1 ;;
  esac
  if [ "$scope" != "global" ] && [ $in_project -eq 0 ]; then
    exec "${{REAL_PY}}" -m pip "$@"
  fi
  if [ "$scope" != "global" ] && [ -n "$EXPECTED_VENV" ]; then
    cur_venv="${{VIRTUAL_ENV:-}}"
    norm_cur_venv="${{cur_venv//\\//}}"
    norm_expected_venv="${{EXPECTED_VENV//\\//}}"
    if [ "$norm_cur_venv" != "$norm_expected_venv" ]; then
      exec "${{REAL_PY}}" -m pip "$@"
    fi
  fi
  if [ "${{1:-}}" = "uninstall" ]; then
    ARGS_STR="$*"
    if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
      "${{REAL_PY}}" -m safedeps.cli guard-cleanup "$ACTIVE_PROJECT_ROOT" >/dev/null 2>&1 || true
      exec "${{REAL_PY}}" -m pip "$@"
    fi
    echo "Blocked: pip uninstall is disabled while SafeDeps guard is active."
    exit 2
  fi
  if [ "${{1:-}}" = "install" ]; then
    shift
    if ! "${{REAL_PY}}" - "$PWD" "$@" <<'PY'
import sys
from pathlib import Path

from safedeps import runtime_guard

root = Path(sys.argv[1])
args = sys.argv[2:]
message = runtime_guard.validate_install_args(root, args)
if message:
    print(message, file=sys.stderr)
    sys.exit(2)
PY
    then
      exit 2
    fi
    set -- install "$@"
  fi
  if [ "${{1:-}}" = "install" ] || [ "${{1:-}}" = "download" ]; then
    ARGS_STR="$*"
    if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
      if [ -z "$OFFICIAL_SAFEDEPS_GIT" ] || ! echo "$ARGS_STR" | grep -Fq "$OFFICIAL_SAFEDEPS_GIT"; then
        echo "Blocked: SafeDeps updates are allowed only from official Git source."
        [ -n "$OFFICIAL_SAFEDEPS_GIT" ] && echo "Allowed source: $OFFICIAL_SAFEDEPS_GIT"
        exit 2
      fi
    fi
  fi
  if ! "${{REAL_PY}}" -m safedeps.cli scan . --fail-on {fail_on}; then
    echo "SafeDeps blocked pip install due to policy/security findings."
    echo "Open UI: safedeps ui . --open-browser"
    exit 2
  fi
fi

exec "${{REAL_PY}}" -m pip "$@"
    """
    # Windows wrappers (PowerShell/CMD) so pip install is guarded automatically.
    pip_ps1 = f"""$PipArgs = $args
$ErrorActionPreference = "Stop"
$OfficialGit = "{official_repo}"
$ProjectRoot = "{str(root)}"
$GuardStateFile = "{str(root / '.safedeps' / 'guard-state.json')}"
$ExpectedVenv = "{expected_venv}"
$StateProjectRoot = $ProjectRoot
if (Test-Path $GuardStateFile) {{
  try {{
    $stateData = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
    if ($stateData.project_root) {{
      $StateProjectRoot = [string]$stateData.project_root
    }}
  }} catch {{}}
}}

& "{real_python}" -c "import safedeps" *> $null
if ($LASTEXITCODE -ne 0) {{
  & "{real_python}" -m pip @PipArgs
  exit $LASTEXITCODE
}}

if ($PipArgs.Length -gt 0 -and ($PipArgs[0].ToLower() -eq "install" -or $PipArgs[0].ToLower() -eq "uninstall" -or $PipArgs[0].ToLower() -eq "download")) {{
  $scope = "project"
  if (Test-Path $GuardStateFile) {{
    try {{
      $st = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
      if ($st.protection_scope -eq "global") {{ $scope = "global" }}
    }} catch {{}}
  }}
$currentPath = ((Get-Location).Path).Replace([char]92, '/').TrimEnd("/")
$stateProjectPath = ($StateProjectRoot).Replace([char]92, '/').TrimEnd("/")
  $inProject = $currentPath.StartsWith($stateProjectPath, [System.StringComparison]::OrdinalIgnoreCase)
  if ($scope -ne "global" -and -not $inProject) {{
    & "{real_python}" -m pip @PipArgs
    exit $LASTEXITCODE
  }}
  if ($scope -ne "global" -and -not [string]::IsNullOrWhiteSpace($ExpectedVenv)) {{
    $normExpectedVenv = ($ExpectedVenv).Replace([char]92, '/').Trim().TrimEnd("/")
    $curVenv = [string]($env:VIRTUAL_ENV)
    $normCurVenv = ($curVenv).Replace([char]92, '/').Trim().TrimEnd("/")
    if ([string]::IsNullOrWhiteSpace($normCurVenv) -or ($normCurVenv -ne $normExpectedVenv)) {{
      & "{real_python}" -m pip @PipArgs
      exit $LASTEXITCODE
    }}
  }}

    if ($PipArgs.Length -gt 0 -and $PipArgs[0].ToLower() -eq "uninstall") {{
    $argsLine = [string]::Join(" ", $PipArgs)
    if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
      & "{real_python}" -m safedeps.cli guard-cleanup $StateProjectRoot *> $null
      & "{real_python}" -m pip @PipArgs
      exit $LASTEXITCODE
    }}
    Write-Host "Blocked: pip uninstall is disabled while SafeDeps guard is active."
    exit 2
  }}

  $expectValueFor = @("-r","--requirement","-c","--constraint","-i","--index-url","--extra-index-url","--find-links","-f")
  $skipNext = $false
  for ($i = 1; $i -lt $PipArgs.Length; $i++) {{
    $tok = [string]$PipArgs[$i]
    if ($skipNext) {{ $skipNext = $false; continue }}
    if ($expectValueFor -contains $tok.ToLower()) {{ $skipNext = $true; continue }}
    if ($tok.StartsWith("-")) {{ continue }}
    $looksLikeWinAbs = ($tok.Length -ge 3 -and [char]::IsLetter($tok[0]) -and $tok[1] -eq ":" -and ($tok[2] -eq "\\" -or $tok[2] -eq "/"))
    if ($tok.StartsWith(".") -or $tok.StartsWith("/") -or $tok.StartsWith("\\") -or $looksLikeWinAbs) {{ continue }}
    if ($tok.EndsWith(".whl") -or $tok.EndsWith(".tar.gz") -or $tok.EndsWith(".zip")) {{ continue }}
    if ($tok.StartsWith("git+") -or $tok.StartsWith("http://") -or $tok.StartsWith("https://") -or $tok.StartsWith("file://")) {{
      Write-Host "Blocked: direct URL/VCS runtime install is not allowed without explicit review."
      exit 2
    }}
    if ($tok -match "(^|\\s)safedeps(\\s|$)") {{ continue }}
    if ($tok -notmatch "==") {{
      Write-Host "Blocked: unpinned runtime install is not allowed. Use exact versions (example: package==1.2.3)."
      exit 2
    }}
  }}
  $argsLine = [string]::Join(" ", $PipArgs)
  if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
    if ([string]::IsNullOrWhiteSpace($OfficialGit) -or ($argsLine -notlike "*$OfficialGit*")) {{
      Write-Host "Blocked: SafeDeps updates are allowed only from official Git source."
      if (-not [string]::IsNullOrWhiteSpace($OfficialGit)) {{ Write-Host "Allowed source: $OfficialGit" }}
      exit 2
    }}
  }}
  & "{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
  if ($LASTEXITCODE -ne 0) {{
    Write-Host "SafeDeps blocked pip install due to policy/security findings."
    Write-Host "Open UI: safedeps ui . --open-browser"
    exit 2
  }}
}}

& "{real_python}" -m pip @PipArgs
exit $LASTEXITCODE
    """
    pip3_ps1 = pip_ps1
    official_repo_cmd = official_repo.replace('"', '')
    if official_repo_cmd:
        cmd_safe_update_check = f"""      echo !_sdargs! | findstr /I /C:"{official_repo_cmd}" >nul
      if errorlevel 1 (
        echo Blocked: SafeDeps updates are allowed only from official Git source.
        echo Allowed source: {official_repo_cmd}
        exit /b 2
      )"""
        py_cmd_safe_update_check = f"""          echo !_sdargs! | findstr /I /C:"{official_repo_cmd}" >nul
          if errorlevel 1 (
            echo Blocked: SafeDeps updates are allowed only from official Git source.
            echo Allowed source: {official_repo_cmd}
            exit /b 2
          )"""
    else:
        cmd_safe_update_check = """      echo Blocked: SafeDeps updates are allowed only from official Git source.
      exit /b 2"""
        py_cmd_safe_update_check = """          echo Blocked: SafeDeps updates are allowed only from official Git source.
          exit /b 2"""
    pip_cmd = f"""@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "_real_python={real_python}"
if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] wrapper=pip.cmd real_python=!_real_python! args=%*
call "!_real_python!" -c "import safedeps" >nul 2>nul
if errorlevel 1 (
  if /I "%~1"=="install" (
    echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
    echo Run safedeps setup again with the Python installation that has SafeDeps installed.
    exit /b 2
  )
  if /I "%~1"=="uninstall" (
    echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
    echo Run safedeps setup again with the Python installation that has SafeDeps installed.
    exit /b 2
  )
  if /I "%~1"=="download" (
    echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
    echo Run safedeps setup again with the Python installation that has SafeDeps installed.
    exit /b 2
  )
  call "!_real_python!" -m pip %*
  exit /b %ERRORLEVEL%
)
set "_should_guard=0"
if /I "%~1"=="install" set "_should_guard=1"
if /I "%~1"=="uninstall" set "_should_guard=1"
if /I "%~1"=="download" set "_should_guard=1"
if /I "!_should_guard!"=="1" (
  set "_scope=project"
  set "_guard_state={str(root / '.safedeps' / 'guard-state.json')}"
  set "_project_root={str(root)}"
  if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] guard_state=!_guard_state!
  for /f "delims=" %%R in ('call "!_real_python!" -c "import json,os,sys; p=sys.argv[1]; print((json.load(open(p)).get('project_root', '') if os.path.exists(p) else ''))" "!_guard_state!"') do set "_project_root=%%R"
  set "_expected_venv={expected_venv}"
  for /f "delims=" %%S in ('call "!_real_python!" -c "import json,os,sys; p=sys.argv[1]; print((json.load(open(p)).get('protection_scope', 'project') if os.path.exists(p) else 'project'))" "!_guard_state!"') do set "_scope=%%S"
  if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] scope=!_scope! project_root=!_project_root! expected_venv=!_expected_venv!
  if /I not "!_scope!"=="global" (
    set "_cd=%CD%"
    set "_cd_norm=!_cd:\\=/!"
    set "_project_root_norm=!_project_root:\\=/!"
    echo !_cd_norm! | findstr /I /B /C:"!_project_root_norm!" >nul
    if errorlevel 1 set "_should_guard=0"
    if not "!_expected_venv!"=="" (
      set "_cur_venv=%VIRTUAL_ENV:\\=/%"
      set "_expected_venv_norm=!_expected_venv:\\=/!"
      if /I "!_cur_venv!" NEQ "!_expected_venv_norm!" set "_should_guard=0"
    )
  )
  if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] should_guard=!_should_guard! cwd=%CD%
  if "!_should_guard!"=="1" (
    if /I "%~1"=="uninstall" (
      set "_sdargs=%*"
      echo !_sdargs! | findstr /I /R "\\<safedeps\\>" >nul
      if not errorlevel 1 (
        call "!_real_python!" -m safedeps.cli guard-cleanup "!_project_root!" >nul 2>nul
        call "!_real_python!" -m pip %*
        exit /b %ERRORLEVEL%
      )
      echo Blocked: pip uninstall is disabled while SafeDeps guard is active.
      exit /b 2
    )
    set "_sdargs=%*"
    echo !_sdargs! | findstr /I /C:"==" >nul
    if errorlevel 1 (
      echo !_sdargs! | findstr /I /C:" -r " /C:" --requirement " /C:"git+" /C:".whl" /C:".tar.gz" /C:".zip" >nul
      if errorlevel 1 (
        echo Blocked: unpinned runtime install is not allowed. Use exact versions ^(example: package==1.2.3^).
        exit /b 2
      )
    )
    set "_sdargs=%*"
    echo !_sdargs! | findstr /I /C:"git+" /C:"http://" /C:"https://" /C:"file://" >nul
    if not errorlevel 1 (
      echo Blocked: direct URL/VCS runtime install is not allowed without explicit review.
      exit /b 2
    )
    echo !_sdargs! | findstr /I /R "\\<safedeps\\>" >nul
    if not errorlevel 1 (
{cmd_safe_update_check}
    )
    call "!_real_python!" -m safedeps.cli scan . --fail-on {fail_on}
    if errorlevel 1 (
      echo SafeDeps blocked pip install due to policy/security findings.
      echo Open UI: safedeps ui . --open-browser
      exit /b 2
    )
  )
)
call "!_real_python!" -m pip %*
exit /b %ERRORLEVEL%
    """
    npm_wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
REAL_PY="{real_python}"
PROJECT_ROOT="{root_posix}"
GUARD_STATE_FILE="{guard_state_posix}"
EXPECTED_VENV="{expected_venv_posix}"
resolve_project_root_from_state() {{
  local project_root="$PROJECT_ROOT"
  if [ -f "$GUARD_STATE_FILE" ]; then
    local state_root
    state_root="$(sed -n 's/.*"project_root"[[:space:]]*:[[:space:]]*"\\(.*\\)".*/\\1/p' "$GUARD_STATE_FILE" | head -n 1)"
    if [ -n "$state_root" ]; then
      project_root="$state_root"
    fi
  fi
  printf "%s" "$project_root"
}}

if [ "${{1:-}}" = "install" ] || [ "${{1:-}}" = "update" ]; then
  sub="${{1:-}}"
  shift
  scope="project"
  if [ -f "$GUARD_STATE_FILE" ] && grep -q '"protection_scope"[[:space:]]*:[[:space:]]*"global"' "$GUARD_STATE_FILE"; then
    scope="global"
  fi
  ACTIVE_PROJECT_ROOT="$(resolve_project_root_from_state)"
  in_project=0
  case "${{PWD}}/" in
    "${{ACTIVE_PROJECT_ROOT}}"/*) in_project=1 ;;
  esac
  if [ "$scope" != "global" ] && [ $in_project -eq 0 ]; then
    exec npm "$sub" "$@"
  fi
  if [ "$scope" != "global" ] && [ -n "$EXPECTED_VENV" ]; then
    cur_venv="${{VIRTUAL_ENV:-}}"
    norm_cur_venv="${{cur_venv//\\//}}"
    norm_expected_venv="${{EXPECTED_VENV//\\//}}"
    if [ "$norm_cur_venv" != "$norm_expected_venv" ]; then
      exec npm "$sub" "$@"
    fi
  fi
  if [ "$sub" = "install" ] || [ "$sub" = "update" ]; then
    for tok in "$@"; do
      case "$tok" in
        -*) continue ;;
      esac
      case "$tok" in
        .*|/*|\\*|[A-Za-z]:\\*|git+*|*.tgz|*.tar.gz|*.zip) continue ;;
      esac
      echo "$tok" | grep -Fq "@" || {{
        echo "Blocked: unpinned runtime npm install/update is not allowed. Use exact versions (example: package@1.2.3)."
        exit 2
      }}
    done
  fi
  if ! "${{REAL_PY}}" -m safedeps.cli scan . --fail-on {fail_on}; then
    echo "SafeDeps blocked npm change due to policy/security findings."
    echo "Open UI: safedeps ui . --open-browser"
    exit 2
  fi
fi
exec npm "$sub" "$@"
    """
    npm_ps1 = f"""$NpmArgs = $args
$ErrorActionPreference = "Stop"
$ProjectRoot = "{str(root)}"
$GuardStateFile = "{str(root / '.safedeps' / 'guard-state.json')}"
$ExpectedVenv = "{expected_venv}"
$StateProjectRoot = $ProjectRoot
if (Test-Path $GuardStateFile) {{
  try {{
    $stateData = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
    if ($stateData.project_root) {{
      $StateProjectRoot = [string]$stateData.project_root
    }}
  }} catch {{}}
}}
if ($NpmArgs.Length -gt 0) {{
  $cmd = $NpmArgs[0].ToLower()
  if ($cmd -eq "install" -or $cmd -eq "update") {{
    $scope = "project"
    if (Test-Path $GuardStateFile) {{
      try {{
        $st = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
        if ($st.protection_scope -eq "global") {{ $scope = "global" }}
      }} catch {{}}
    }}
    $currentPath = ((Get-Location).Path).Replace([char]92, '/').TrimEnd("/")
    $stateProjectPath = ($StateProjectRoot).Replace([char]92, '/').TrimEnd("/")
    $inProject = $currentPath.StartsWith($stateProjectPath, [System.StringComparison]::OrdinalIgnoreCase)
    if ($scope -ne "global" -and -not $inProject) {{
      & npm @NpmArgs
      exit $LASTEXITCODE
    }}
    if ($scope -ne "global" -and -not [string]::IsNullOrWhiteSpace($ExpectedVenv)) {{
      $normExpectedVenv = ($ExpectedVenv).Replace([char]92, '/').Trim().TrimEnd("/")
      $curVenv = [string]($env:VIRTUAL_ENV)
      $normCurVenv = ($curVenv).Replace([char]92, '/').Trim().TrimEnd("/")
      if ([string]::IsNullOrWhiteSpace($normCurVenv) -or ($normCurVenv -ne $normExpectedVenv)) {{
        & npm @NpmArgs
        exit $LASTEXITCODE
      }}
    }}
    for ($i=1; $i -lt $NpmArgs.Length; $i++) {{
      $tok = [string]$NpmArgs[$i]
      if ($tok.StartsWith("-")) {{ continue }}
      $looksLikeWinAbs = ($tok.Length -ge 3 -and [char]::IsLetter($tok[0]) -and $tok[1] -eq ":" -and ($tok[2] -eq "\\" -or $tok[2] -eq "/"))
      if ($tok.StartsWith(".") -or $tok.StartsWith("/") -or $tok.StartsWith("\\") -or $looksLikeWinAbs) {{ continue }}
      if ($tok.StartsWith("git+") -or $tok.EndsWith(".tgz") -or $tok.EndsWith(".tar.gz") -or $tok.EndsWith(".zip")) {{ continue }}
      if ($tok -notmatch "@") {{
        Write-Host "Blocked: unpinned runtime npm install/update is not allowed. Use exact versions (example: package@1.2.3)."
        exit 2
      }}
    }}
    & "{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
    if ($LASTEXITCODE -ne 0) {{
      Write-Host "SafeDeps blocked npm change due to policy/security findings."
      Write-Host "Open UI: safedeps ui . --open-browser"
      exit 2
    }}
  }}
}}
& npm @NpmArgs
exit $LASTEXITCODE
    """
    npm_cmd = f"""@echo off
setlocal EnableExtensions EnableDelayedExpansion
if /I "%~1"=="install" goto :check
if /I "%~1"=="update" goto :check
goto :run
:check
set "_should_guard=1"
set "_scope=project"
set "_guard_state={str(root / '.safedeps' / 'guard-state.json')}"
set "_project_root={str(root)}"
for /f "delims=" %%R in ('"{real_python}" -c "import json,os,sys; p=sys.argv[1]; print((json.load(open(p)).get('project_root', '') if os.path.exists(p) else ''))" "!_guard_state!"') do set "_project_root=%%R"
set "_expected_venv={expected_venv}"
if exist "{str(root / '.safedeps' / 'guard-state.json')}" (
  findstr /I /C:"\"protection_scope\": \"global\"" "{str(root / '.safedeps' / 'guard-state.json')}" >nul
  if not errorlevel 1 set "_scope=global"
)
if /I not "!_scope!"=="global" (
  set "_cd=%CD%"
  set "_cd_norm=!_cd:\\=/!"
  set "_project_root_norm=!_project_root:\\=/!"
  echo !_cd_norm! | findstr /I /B /C:"!_project_root_norm!" >nul
  if errorlevel 1 set "_should_guard=0"
  if not "!_expected_venv!"=="" (
    set "_cur_venv=%VIRTUAL_ENV:\\=/%"
    set "_expected_venv_norm=!_expected_venv:\\=/!"
    if /I "!_cur_venv!" NEQ "!_expected_venv_norm!" set "_should_guard=0"
  )
)
if not "!_should_guard!"=="1" goto :run
if "%~2"=="" goto :scan
echo %* | findstr /I /C:"@" /C:".tgz" /C:".tar.gz" /C:".zip" /C:"git+" >nul
if errorlevel 1 (
  echo Blocked: unpinned runtime npm install/update is not allowed. Use exact versions ^(example: package@1.2.3^).
  exit /b 2
)
:scan
"{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
if errorlevel 1 (
  echo SafeDeps blocked npm change due to policy/security findings.
  echo Open UI: safedeps ui . --open-browser
  exit /b 2
)
:run
npm %*
exit /b %ERRORLEVEL%
    """
    python_wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
REAL_PY="{real_python}"
OFFICIAL_SAFEDEPS_GIT="{official_repo}"
PROJECT_ROOT="{root_posix}"
GUARD_STATE_FILE="{guard_state_posix}"
EXPECTED_VENV="{expected_venv_posix}"
resolve_project_root_from_state() {{
  local project_root="$PROJECT_ROOT"
  if [ -f "$GUARD_STATE_FILE" ]; then
    local state_root
    state_root="$(sed -n 's/.*"project_root"[[:space:]]*:[[:space:]]*"\\(.*\\)".*/\\1/p' "$GUARD_STATE_FILE" | head -n 1)"
    if [ -n "$state_root" ]; then
      project_root="$state_root"
    fi
  fi
  printf "%s" "$project_root"
}}

if ! "${{REAL_PY}}" -c "import safedeps" >/dev/null 2>&1; then
  exec "${{REAL_PY}}" "$@"
fi
if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "pip" ]; then
  sub="${{3:-}}"
  if [ "$sub" = "install" ] || [ "$sub" = "uninstall" ] || [ "$sub" = "download" ]; then
  scope="project"
  if [ -f "$GUARD_STATE_FILE" ] && grep -q '"protection_scope"[[:space:]]*:[[:space:]]*"global"' "$GUARD_STATE_FILE"; then
    scope="global"
  fi
    ACTIVE_PROJECT_ROOT="$(resolve_project_root_from_state)"
    in_project=0
    case "${{PWD}}/" in
      "${{ACTIVE_PROJECT_ROOT}}"/*) in_project=1 ;;
    esac
  if [ "$scope" != "global" ] && [ $in_project -eq 0 ]; then
      exec "${{REAL_PY}}" "$@"
    fi
  if [ "$scope" != "global" ] && [ -n "$EXPECTED_VENV" ]; then
    cur_venv="${{VIRTUAL_ENV:-}}"
    norm_cur_venv="${{cur_venv//\\//}}"
    norm_expected_venv="${{EXPECTED_VENV//\\//}}"
    if [ "$norm_cur_venv" != "$norm_expected_venv" ]; then
      exec "${{REAL_PY}}" "$@"
    fi
  fi
  if [ "$sub" = "uninstall" ]; then
    ARGS_STR="$*"
    if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
      "${{REAL_PY}}" -m safedeps.cli guard-cleanup "$ACTIVE_PROJECT_ROOT" >/dev/null 2>&1 || true
      exec "${{REAL_PY}}" "$@"
    fi
    echo "Blocked: python -m pip uninstall is disabled while SafeDeps guard is active."
    exit 2
  fi
  if [ "$sub" = "install" ]; then
      install_args=("${{@:4}}")
      if ! "${{REAL_PY}}" - "$PWD" "${{install_args[@]}}" <<'PY'
import sys
from pathlib import Path

from safedeps import runtime_guard

root = Path(sys.argv[1])
args = sys.argv[2:]
message = runtime_guard.validate_install_args(root, args)
if message:
    print(message, file=sys.stderr)
    sys.exit(2)
PY
      then
        exit 2
      fi
    fi
    ARGS_STR="$*"
    if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
      if [ -z "$OFFICIAL_SAFEDEPS_GIT" ] || ! echo "$ARGS_STR" | grep -Fq "$OFFICIAL_SAFEDEPS_GIT"; then
        echo "Blocked: SafeDeps updates are allowed only from official Git source."
        [ -n "$OFFICIAL_SAFEDEPS_GIT" ] && echo "Allowed source: $OFFICIAL_SAFEDEPS_GIT"
        exit 2
      fi
    fi
    if ! "${{REAL_PY}}" -m safedeps.cli scan . --fail-on {fail_on}; then
      echo "SafeDeps blocked python -m pip due to policy/security findings."
      echo "Open UI: safedeps ui . --open-browser"
      exit 2
    fi
  fi
fi
exec "$REAL_PY" "$@"
    """
    python_ps1 = f"""$PyArgs = $args
$ErrorActionPreference = "Stop"
$OfficialGit = "{official_repo}"
$ProjectRoot = "{str(root)}"
$GuardStateFile = "{str(root / '.safedeps' / 'guard-state.json')}"
$ExpectedVenv = "{expected_venv}"
$StateProjectRoot = $ProjectRoot
if (Test-Path $GuardStateFile) {{
  try {{
    $stateData = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
    if ($stateData.project_root) {{
      $StateProjectRoot = [string]$stateData.project_root
    }}
  }} catch {{}}
}}

& "{real_python}" -c "import safedeps" *> $null
if ($LASTEXITCODE -ne 0) {{
  & "{real_python}" @PyArgs
  exit $LASTEXITCODE
}}

$shouldGuard = $false
if ($PyArgs.Length -ge 3 -and $PyArgs[0] -eq "-m" -and $PyArgs[1].ToLower() -eq "pip") {{
  $sub = $PyArgs[2].ToLower()
  if ($sub -eq "install" -or $sub -eq "uninstall" -or $sub -eq "download") {{
    $shouldGuard = $true
  }}
}}

if ($shouldGuard) {{
  $scope = "project"
  if (Test-Path $GuardStateFile) {{
    try {{
      $st = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
      if ($st.protection_scope -eq "global") {{ $scope = "global" }}
    }} catch {{}}
  }}
  $currentPath = ((Get-Location).Path).Replace([char]92, '/').TrimEnd("/")
  $stateProjectPath = ($StateProjectRoot).Replace([char]92, '/').TrimEnd("/")
  $inProject = $currentPath.StartsWith($stateProjectPath, [System.StringComparison]::OrdinalIgnoreCase)
  if ($scope -ne "global" -and -not $inProject) {{
    & "{real_python}" @PyArgs
    exit $LASTEXITCODE
  }}
  if ($scope -ne "global" -and -not [string]::IsNullOrWhiteSpace($ExpectedVenv)) {{
    $normExpectedVenv = ($ExpectedVenv).Replace([char]92, '/').Trim().TrimEnd("/")
    $curVenv = [string]($env:VIRTUAL_ENV)
    $normCurVenv = ($curVenv).Replace([char]92, '/').Trim().TrimEnd("/")
    if ([string]::IsNullOrWhiteSpace($normCurVenv) -or ($normCurVenv -ne $normExpectedVenv)) {{
      & "{real_python}" @PyArgs
      exit $LASTEXITCODE
    }}
  }}
  if ($PyArgs.Length -ge 3 -and $PyArgs[0] -eq "-m" -and $PyArgs[1].ToLower() -eq "pip" -and $PyArgs[2].ToLower() -eq "uninstall") {{
    $argsLine = [string]::Join(" ", $PyArgs)
    if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
      & "{real_python}" -m safedeps.cli guard-cleanup $StateProjectRoot *> $null
      & "{real_python}" @PyArgs
      exit $LASTEXITCODE
    }}
    Write-Host "Blocked: python -m pip uninstall is disabled while SafeDeps guard is active."
    exit 2
  }}
  if ($PyArgs.Length -ge 3 -and $PyArgs[2].ToLower() -eq "install") {{
    $expectValueFor = @("-r","--requirement","-c","--constraint","-i","--index-url","--extra-index-url","--find-links","-f")
    $skipNext = $false
    for ($i = 3; $i -lt $PyArgs.Length; $i++) {{
      $tok = [string]$PyArgs[$i]
      if ($skipNext) {{ $skipNext = $false; continue }}
      if ($expectValueFor -contains $tok.ToLower()) {{ $skipNext = $true; continue }}
      if ($tok.StartsWith("-")) {{ continue }}
      $looksLikeWinAbs = ($tok.Length -ge 3 -and [char]::IsLetter($tok[0]) -and $tok[1] -eq ":" -and ($tok[2] -eq "\\" -or $tok[2] -eq "/"))
      if ($tok.StartsWith(".") -or $tok.StartsWith("/") -or $tok.StartsWith("\\") -or $looksLikeWinAbs) {{ continue }}
      if ($tok.EndsWith(".whl") -or $tok.EndsWith(".tar.gz") -or $tok.EndsWith(".zip")) {{ continue }}
      if ($tok.StartsWith("git+") -or $tok.StartsWith("http://") -or $tok.StartsWith("https://") -or $tok.StartsWith("file://")) {{
        Write-Host "Blocked: direct URL/VCS runtime install is not allowed without explicit review."
        exit 2
      }}
      if ($tok -match "(^|\\s)safedeps(\\s|$)") {{ continue }}
      if ($tok -notmatch "==") {{
        Write-Host "Blocked: unpinned runtime install is not allowed. Use exact versions (example: package==1.2.3)."
        exit 2
      }}
    }}
  }}
  if ($sub -eq "install" -or $sub -eq "download") {{
    $argsLine = [string]::Join(" ", $PyArgs)
    if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
      if ([string]::IsNullOrWhiteSpace($OfficialGit) -or ($argsLine -notlike "*$OfficialGit*")) {{
        Write-Host "Blocked: SafeDeps updates are allowed only from official Git source."
        if (-not [string]::IsNullOrWhiteSpace($OfficialGit)) {{ Write-Host "Allowed source: $OfficialGit" }}
        exit 2
      }}
    }}
  }}
  & "{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
  if ($LASTEXITCODE -ne 0) {{
    Write-Host "SafeDeps blocked python -m pip due to policy/security findings."
    Write-Host "Open UI: safedeps ui . --open-browser"
    exit 2
  }}
}}

& "{real_python}" @PyArgs
exit $LASTEXITCODE
    """
    python_cmd = f"""@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "_real_python={real_python}"
if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] wrapper=python.cmd real_python=!_real_python! args=%*
call "!_real_python!" -c "import safedeps" >nul 2>nul
if errorlevel 1 (
  if /I "%~1"=="-m" if /I "%~2"=="pip" (
    if /I "%~3"=="install" (
      echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
      echo Run safedeps setup again with the Python installation that has SafeDeps installed.
      exit /b 2
    )
    if /I "%~3"=="uninstall" (
      echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
      echo Run safedeps setup again with the Python installation that has SafeDeps installed.
      exit /b 2
    )
    if /I "%~3"=="download" (
      echo Blocked: SafeDeps guard wrapper is active, but SafeDeps is not importable by !_real_python!.
      echo Run safedeps setup again with the Python installation that has SafeDeps installed.
      exit /b 2
    )
  )
  call "!_real_python!" %*
  exit /b %ERRORLEVEL%
)
set "_should_guard=0"
if /I "%~1"=="-m" if /I "%~2"=="pip" (
if /I "%~3"=="install" set "_should_guard=1"
if /I "%~3"=="uninstall" set "_should_guard=1"
if /I "%~3"=="download" set "_should_guard=1"
if "!_should_guard!"=="1" (
  set "_scope=project"
  set "_guard_state={str(root / '.safedeps' / 'guard-state.json')}"
  set "_project_root={str(root)}"
  if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] guard_state=!_guard_state!
  for /f "delims=" %%R in ('call "!_real_python!" -c "import json,os,sys; p=sys.argv[1]; print((json.load(open(p)).get('project_root', '') if os.path.exists(p) else ''))" "!_guard_state!"') do set "_project_root=%%R"
  set "_expected_venv={expected_venv}"
  for /f "delims=" %%S in ('call "!_real_python!" -c "import json,os,sys; p=sys.argv[1]; print((json.load(open(p)).get('protection_scope', 'project') if os.path.exists(p) else 'project'))" "!_guard_state!"') do set "_scope=%%S"
  if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] scope=!_scope! project_root=!_project_root! expected_venv=!_expected_venv!
  if /I not "!_scope!"=="global" (
    set "_cd=%CD%"
  set "_cd_norm=!_cd:\\=/!"
  set "_project_root_norm=!_project_root:\\=/!"
    echo !_cd_norm! | findstr /I /B /C:"!_project_root_norm!" >nul
    if errorlevel 1 set "_should_guard=0"
    if not "!_expected_venv!"=="" (
      set "_cur_venv=%VIRTUAL_ENV:\\=/%"
      set "_expected_venv_norm=!_expected_venv:\\=/!"
      if /I "!_cur_venv!" NEQ "!_expected_venv_norm!" set "_should_guard=0"
    )
  )
    if /I "%SAFEDEPS_DEBUG%"=="1" echo [SafeDeps CMD debug] should_guard=!_should_guard! cwd=%CD%
    if "!_should_guard!"=="1" (
      if /I "%~3"=="uninstall" (
        set "_sdargs=%*"
        echo !_sdargs! | findstr /I /R "\\<safedeps\\>" >nul
        if not errorlevel 1 (
          call "!_real_python!" -m safedeps.cli guard-cleanup "!_project_root!" >nul 2>nul
          call "!_real_python!" %*
          exit /b %ERRORLEVEL%
        )
        echo Blocked: python -m pip uninstall is disabled while SafeDeps guard is active.
        exit /b 2
      )
      if /I "%~3"=="install" (
        set "_sdargs=%*"
        echo !_sdargs! | findstr /I /C:"==" >nul
        if errorlevel 1 (
          echo !_sdargs! | findstr /I /C:" -r " /C:" --requirement " /C:"git+" /C:".whl" /C:".tar.gz" /C:".zip" >nul
          if errorlevel 1 (
            echo Blocked: unpinned runtime install is not allowed. Use exact versions ^(example: package==1.2.3^).
            exit /b 2
          )
        )
      )
      if /I "%~3"=="install" (
        set "_sdargs=%*"
        echo !_sdargs! | findstr /I /C:"git+" /C:"http://" /C:"https://" /C:"file://" >nul
        if not errorlevel 1 (
          echo Blocked: direct URL/VCS runtime install is not allowed without explicit review.
          exit /b 2
        )
        echo !_sdargs! | findstr /I /R "\\<safedeps\\>" >nul
        if not errorlevel 1 (
{py_cmd_safe_update_check}
        )
      )
      call "!_real_python!" -m safedeps.cli scan . --fail-on {fail_on}
      if errorlevel 1 (
        echo SafeDeps blocked python -m pip due to policy/security findings.
        echo Open UI: safedeps ui . --open-browser
        exit /b 2
      )
    )
  )
)
call "!_real_python!" %*
exit /b %ERRORLEVEL%
    """
    activate_ps1 = (
        '$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n'
        '$projectRoot = Split-Path -Parent $scriptDir\n'
        '$safeDepsBin = Join-Path $projectRoot ".safedeps/bin"\n'
        '$hasSafeDeps = $false\n'
        'try {\n'
        '  & python -c "import safedeps" *> $null\n'
        '  if ($LASTEXITCODE -eq 0) { $hasSafeDeps = $true }\n'
        '} catch {}\n'
        'if (-not $hasSafeDeps) {\n'
        '  $markerStart = "# >>> SafeDeps Auto Guard >>>"\n'
        '  $markerEnd = "# <<< SafeDeps Auto Guard <<<"\n'
        '  $profiles = @(\n'
        '    (Join-Path $HOME "Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1"),\n'
        '    (Join-Path $HOME "Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1")\n'
        '  )\n'
        '  foreach ($p in $profiles) {\n'
        '    if (Test-Path $p) {\n'
        '      $c = Get-Content $p -Raw\n'
        '      $rx = [regex]::Escape($markerStart) + ".*?" + [regex]::Escape($markerEnd) + "\\r?\\n?"\n'
        '      $nc = [regex]::Replace($c, $rx, "", "Singleline")\n'
        '      if ($nc -ne $c) { Set-Content $p $nc }\n'
        '    }\n'
        '  }\n'
        '  Remove-Item Function:\\pip -ErrorAction SilentlyContinue\n'
        '  Remove-Item Function:\\pip3 -ErrorAction SilentlyContinue\n'
        '  Remove-Item Function:\\python -ErrorAction SilentlyContinue\n'
        '  Remove-Item Function:\\python3 -ErrorAction SilentlyContinue\n'
        '  Remove-Item Function:\\npm -ErrorAction SilentlyContinue\n'
        '  return\n'
        '}\n'
        '$env:PATH = "$safeDepsBin;$env:PATH"\n'
        'Remove-Item Function:\\pip -ErrorAction SilentlyContinue\n'
        'Remove-Item Function:\\pip3 -ErrorAction SilentlyContinue\n'
        'Remove-Item Function:\\python -ErrorAction SilentlyContinue\n'
        'Remove-Item Function:\\python3 -ErrorAction SilentlyContinue\n'
        'Remove-Item Function:\\npm -ErrorAction SilentlyContinue\n'
        '$global:__safedeps_pip_cmd = Join-Path $safeDepsBin "pip.ps1"\n'
        '$global:__safedeps_py_cmd = Join-Path $safeDepsBin "python.ps1"\n'
        '$global:__safedeps_npm_cmd = Join-Path $safeDepsBin "npm.ps1"\n'
        'function global:pip { & $global:__safedeps_pip_cmd @args }\n'
        'function global:pip3 { & (Join-Path $safeDepsBin "pip3.ps1") @args }\n'
        'function global:npm { & $global:__safedeps_npm_cmd @args }\n'
        'function global:python { & $global:__safedeps_py_cmd @args }\n'
        'function global:python3 { & (Join-Path $safeDepsBin "python3.ps1") @args }\n'
        'Write-Host "SafeDeps pip guard active for this PowerShell session."\n'
    )
    guard_install = write_guard_backend_files(
        root,
        bindir,
        posix_bindir,
        GuardBackendFiles(
            pip_wrapper=wrapper,
            pip_ps1=pip_ps1,
            pip3_ps1=pip3_ps1,
            pip_cmd=pip_cmd,
            npm_wrapper=npm_wrapper,
            npm_ps1=npm_ps1,
            npm_cmd=npm_cmd,
            python_wrapper=python_wrapper,
            python_ps1=python_ps1,
            python_cmd=python_cmd,
            activate_ps1=activate_ps1,
        ),
        windows=_is_windows(),
    )
    pip_path = guard_install.pip_path
    pip3_path = guard_install.pip3_path
    activate = guard_install.activate
    activate_bat = guard_install.activate_bat
    activate_ps1_path = guard_install.activate_ps1

    print("SafeDeps setup completed.")
    if official_repo:
        print(f"- Official SafeDeps Git source enforced: {official_repo}")
    else:
        print("- Official SafeDeps Git source not detected (remote.origin.url missing). SafeDeps self-update will be blocked.")
    if _is_windows():
        print(f"- Guard wrappers: {bindir / 'pip.cmd'} and {bindir / 'pip3.cmd'}")
    else:
        print(f"- Guard wrappers: {pip_path} and {pip3_path}")
    interpreter_hook = install_interpreter_guard_hook(root, expected_venv, official_repo)
    _state = _load_guard_state(root)
    if project_install:
        _state["protection_scope"] = "project"
    elif requested_protection_scope in ("project", "global"):
        _state["protection_scope"] = requested_protection_scope
    elif str(install_scope or "").strip().lower() == "system":
        _state["protection_scope"] = "global"
    elif not _state.get("protection_scope") or _state.get("protection_scope") not in ("project", "global"):
        _state["protection_scope"] = default_scope
    _state["project_root"] = str(root)
    _state["fail_on"] = fail_on
    _state["auto_guard"] = previous_auto_guard
    _state["auto_guard_powershell"] = previous_auto_guard
    auto_guard = previous_auto_guard
    _write_guard_state(root, _state)
    # Hard resync of profile hooks on reinstall/setup with verification.
    try:
        _force_autoguard_resync(root, auto_guard)
    except Exception:
        pass
    _state = _load_guard_state(root)
    _state["project_root"] = str(root)
    _write_guard_state(root, _state)
    print(f"- Protection scope default: {_state['protection_scope']}")
    print(f"- Activate in bash/zsh: source {activate}")
    print(f"- Activate in CMD: {activate_bat}")
    print(f"- Activate in PowerShell: . {activate_ps1_path}")
    if interpreter_hook:
        print(f"- Python interpreter guard hook: {interpreter_hook}")
    else:
        print("- Python interpreter guard hook: not installed (site-packages not writable or test environment).")
    print("- After activation, pip install is guarded automatically in this project shell/session.")
    return 0
