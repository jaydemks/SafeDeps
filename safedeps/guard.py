from __future__ import annotations

import json
import os
import subprocess
import sys
import re
import shutil
from pathlib import Path

from .policy import DEFAULT_POLICY


def _init_project(root: Path, force: bool):
    target = root / ".safedeps" / "policy.json"
    if target.exists() and not force:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
def cmd_setup(args):
    root = Path(args.path).resolve()
    fail_on = "CRITICAL"
    real_python = str(Path(sys.executable).resolve())
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
    expect_val=0
    for tok in "$@"; do
      if [ $expect_val -eq 1 ]; then expect_val=0; continue; fi
      case "$tok" in
        -r|--requirement|-c|--constraint|-i|--index-url|--extra-index-url|--find-links|-f) expect_val=1; continue ;;
        -*) continue ;;
      esac
      case "$tok" in
        .*|/*|\\*|[A-Za-z]:\\*|git+*|*.whl|*.tar.gz|*.zip) continue ;;
      esac
      echo "$tok" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)" && continue
      if ! echo "$tok" | grep -Fq "=="; then
        echo "Blocked: unpinned runtime install is not allowed. Use exact versions (example: package==1.2.3)."
        exit 2
      fi
    done
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
    pip_path = posix_bindir / "pip"
    pip3_path = posix_bindir / "pip3"
    pip_path.write_text(wrapper, encoding="utf-8", newline="\n")
    pip3_path.write_text(wrapper, encoding="utf-8", newline="\n")
    os.chmod(pip_path, 0o755)
    os.chmod(pip3_path, 0o755)

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
    if ($tok.StartsWith("git+") -or $tok.EndsWith(".whl") -or $tok.EndsWith(".tar.gz") -or $tok.EndsWith(".zip")) {{ continue }}
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
      expect_val=0
      i=0
      for tok in "$@"; do
        i=$((i+1))
        [ $i -le 3 ] && continue
        if [ $expect_val -eq 1 ]; then expect_val=0; continue; fi
        case "$tok" in
          -r|--requirement|-c|--constraint|-i|--index-url|--extra-index-url|--find-links|-f) expect_val=1; continue ;;
          -*) continue ;;
        esac
        case "$tok" in
          .*|/*|\\*|[A-Za-z]:\\*|git+*|*.whl|*.tar.gz|*.zip) continue ;;
        esac
        echo "$tok" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)" && continue
        if ! echo "$tok" | grep -Fq "=="; then
          echo "Blocked: unpinned runtime install is not allowed. Use exact versions (example: package==1.2.3)."
          exit 2
        fi
      done
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
      if ($tok.StartsWith("git+") -or $tok.EndsWith(".whl") -or $tok.EndsWith(".tar.gz") -or $tok.EndsWith(".zip")) {{ continue }}
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
    (bindir / "pip.ps1").write_text(pip_ps1, encoding="utf-8")
    (bindir / "pip3.ps1").write_text(pip3_ps1, encoding="utf-8")
    (bindir / "pip.cmd").write_text(pip_cmd, encoding="utf-8")
    (bindir / "pip3.cmd").write_text(pip_cmd, encoding="utf-8")
    (posix_bindir / "npm").write_text(npm_wrapper, encoding="utf-8", newline="\n")
    os.chmod(posix_bindir / "npm", 0o755)
    (bindir / "npm.ps1").write_text(npm_ps1, encoding="utf-8")
    (bindir / "npm.cmd").write_text(npm_cmd, encoding="utf-8")
    (posix_bindir / "python").write_text(python_wrapper, encoding="utf-8", newline="\n")
    (posix_bindir / "python3").write_text(python_wrapper, encoding="utf-8", newline="\n")
    os.chmod(posix_bindir / "python", 0o755)
    os.chmod(posix_bindir / "python3", 0o755)
    (bindir / "python.ps1").write_text(python_ps1, encoding="utf-8")
    (bindir / "python3.ps1").write_text(python_ps1, encoding="utf-8")
    (bindir / "python.cmd").write_text(python_cmd, encoding="utf-8")
    (bindir / "python3.cmd").write_text(python_cmd, encoding="utf-8")

    activate = root / ".safedeps" / "activate.sh"
    activate_path = "$PWD/.safedeps/bin-posix" if _is_windows() else "$PWD/.safedeps/bin"
    activate.write_text(
        "#!/usr/bin/env bash\n"
        f'export PATH="{activate_path}:$PATH"\n'
        'echo "SafeDeps pip guard active for this shell."\n',
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(activate, 0o755)

    activate_bat = root / ".safedeps" / "activate.bat"
    activate_bat.write_text(
        "@echo off\r\n"
        "set \"safeDepsBin=%~dp0bin\"\r\n"
        "set \"PATH=%safeDepsBin%;%PATH%\"\r\n"
        "echo SafeDeps pip guard active for this CMD session.\r\n",
        encoding="utf-8",
    )

    activate_ps1 = root / ".safedeps" / "activate.ps1"
    activate_ps1.write_text(
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
        'Write-Host "SafeDeps pip guard active for this PowerShell session."\n',
        encoding="utf-8",
    )

    print("SafeDeps setup completed.")
    if official_repo:
        print(f"- Official SafeDeps Git source enforced: {official_repo}")
    else:
        print("- Official SafeDeps Git source not detected (remote.origin.url missing). SafeDeps self-update will be blocked.")
    if _is_windows():
        print(f"- Guard wrappers: {bindir / 'pip.cmd'} and {bindir / 'pip3.cmd'}")
    else:
        print(f"- Guard wrappers: {pip_path} and {pip3_path}")
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
    print(f"- Activate in PowerShell: . {activate_ps1}")
    print("- After activation, pip install is guarded automatically in this project shell/session.")
    return 0

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
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
            raw, _ = winreg.QueryValueEx(key, "Path")
            return [p for p in str(raw).split(";") if p] if raw else []
    except Exception:
        return []

def _write_user_path_entries_windows(entries: list[str]):
    if not _is_windows():
        return False
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(entries))
        return True
    except Exception:
        return False


def _get_cmd_autorun_windows():
    if not _is_windows():
        return ""
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor", 0, winreg.KEY_READ) as key:
            raw, _ = winreg.QueryValueEx(key, "AutoRun")
            return str(raw or "")
    except Exception:
        return ""


def _write_cmd_autorun_windows(value: str):
    if not _is_windows():
        return False
    try:
        import winreg  # type: ignore
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor", 0, winreg.KEY_SET_VALUE) as key:
            if value.strip():
                winreg.SetValueEx(key, "AutoRun", 0, winreg.REG_EXPAND_SZ, value)
            else:
                try:
                    winreg.DeleteValue(key, "AutoRun")
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False


def _is_safedeps_bindir_entry(path_entry: str):
    normalized = str(path_entry).strip().replace("\\", "/").lower()
    return ".safedeps/bin" in normalized


def _filter_guard_path_entries(entries: list[str], keep_guard_bin: str | None):
    keep_norm = str(keep_guard_bin).strip().lower().replace("\\", "/") if keep_guard_bin else None
    filtered = []
    seen = set()
    for raw in entries:
        raw_str = str(raw).strip()
        if not raw_str:
            continue
        raw_norm = raw_str.lower().replace("\\", "/")
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
    cleaned = re.sub(r"^&\s*|\s*&$", "", cleaned).strip()
    return cleaned

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
        profile.parent.mkdir(parents=True, exist_ok=True)
        content = profile.read_text(encoding="utf-8") if profile.exists() else ""
        cleaned = _strip_autoguard_blocks(content)
        if enable:
            updated = cleaned
            if updated and not updated.endswith("\n"):
                updated += "\n"
            updated += snippet
            if updated != content:
                profile.write_text(updated, encoding="utf-8")
                updated_any = True
        else:
            updated = cleaned
            if updated != content:
                profile.write_text(updated, encoding="utf-8")
                updated_any = True
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
    guard_bin = str((root / ".safedeps" / "bin").resolve()).lower()
    if _is_windows():
        return any(str(e).strip().lower() == guard_bin for e in _get_user_path_entries_windows())
    return any(str(e).strip().lower() == guard_bin for e in os.environ.get("PATH", "").split(os.pathsep) if e)

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

def detect_official_repo_url(root: Path):
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()
    except Exception:
        return ""

def get_current_shell_guard_status(root: Path):
    bindir = str((root / ".safedeps" / "bin").resolve())
    path_value = os.environ.get("PATH", "")
    entries = path_value.split(os.pathsep)
    normalized = [str(Path(p).resolve()) if p else "" for p in entries]
    if bindir in normalized:
        return "ACTIVE (wrapper path present)."
    return "INACTIVE (wrapper path not found in current PATH)."
