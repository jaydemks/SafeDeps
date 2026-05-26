from __future__ import annotations

import json
import os
import subprocess
import sys
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
    default_scope = "project" if (getattr(sys, "base_prefix", sys.prefix) != sys.prefix) else "global"
    root_posix = str(root).replace("\\", "/")
    guard_state_posix = str(root / ".safedeps" / "guard-state.json").replace("\\", "/")
    expected_venv = str(Path(sys.prefix).resolve()) if (getattr(sys, "base_prefix", sys.prefix) != sys.prefix) else ""
    expected_venv_posix = expected_venv.replace("\\", "/")
    _init_project(root, args.force)
    bindir = root / ".safedeps" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)

    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail

REAL_PY="{real_python}"
OFFICIAL_SAFEDEPS_GIT="{official_repo}"
PROJECT_ROOT="{root_posix}"
GUARD_STATE_FILE="{guard_state_posix}"
EXPECTED_VENV="{expected_venv_posix}"

if ! "${{REAL_PY}}" -c "import safedeps" >/dev/null 2>&1; then
  exec "${{REAL_PY}}" -m pip "$@"
fi

if [ "${{1:-}}" = "install" ] || [ "${{1:-}}" = "uninstall" ] || [ "${{1:-}}" = "download" ]; then
  if [ "${{1:-}}" = "uninstall" ]; then
    ARGS_STR="$*"
    if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
      "${{REAL_PY}}" -m safedeps.cli guard-cleanup "$PROJECT_ROOT" >/dev/null 2>&1 || true
      exec "${{REAL_PY}}" -m pip "$@"
    fi
  fi
  scope="project"
  if [ -f "$GUARD_STATE_FILE" ] && grep -q '"protection_scope"[[:space:]]*:[[:space:]]*"global"' "$GUARD_STATE_FILE"; then
    scope="global"
  fi
  in_project=0
  case "${{PWD}}/" in
    "${{PROJECT_ROOT}}"/*) in_project=1 ;;
  esac
  if [ "$scope" != "global" ] && [ $in_project -eq 0 ]; then
    exec "${{REAL_PY}}" -m pip "$@"
  fi
  if [ "$scope" != "global" ] && [ -n "$EXPECTED_VENV" ]; then
    cur_venv="${{VIRTUAL_ENV:-}}"
    if [ "$cur_venv" != "$EXPECTED_VENV" ]; then
      exec "${{REAL_PY}}" -m pip "$@"
    fi
  elif [ "$scope" != "global" ]; then
    # If expected venv was not captured, enforce only when an active venv exists.
    if [ -z "${{VIRTUAL_ENV:-}}" ]; then
      exec "${{REAL_PY}}" -m pip "$@"
    fi
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
    pip_path = bindir / "pip"
    pip3_path = bindir / "pip3"
    pip_path.write_text(wrapper, encoding="utf-8")
    pip3_path.write_text(wrapper, encoding="utf-8")
    os.chmod(pip_path, 0o755)
    os.chmod(pip3_path, 0o755)

    # Windows wrappers (PowerShell/CMD) so pip install is guarded automatically.
    pip_ps1 = f"""$PipArgs = $args
$ErrorActionPreference = "Stop"
$OfficialGit = "{official_repo}"
$ProjectRoot = "{str(root)}"
$GuardStateFile = "{str(root / '.safedeps' / 'guard-state.json')}"
$ExpectedVenv = "{expected_venv}"

& "{real_python}" -c "import safedeps" *> $null
if ($LASTEXITCODE -ne 0) {{
  & "{real_python}" -m pip @PipArgs
  exit $LASTEXITCODE
}}

if ($PipArgs.Length -gt 0 -and $PipArgs[0].ToLower() -eq "uninstall") {{
  $argsLine = [string]::Join(" ", $PipArgs)
  if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
    & "{real_python}" -m safedeps.cli guard-cleanup "{str(root)}" *> $null
    & "{real_python}" -m pip @PipArgs
    exit $LASTEXITCODE
  }}
}}

$isInstall = $false
if ($PipArgs.Length -gt 0 -and $PipArgs[0].ToLower() -eq "install") {{
  $isInstall = $true
}}

if ($isInstall) {{
  $scope = "project"
  if (Test-Path $GuardStateFile) {{
    try {{
      $st = Get-Content $GuardStateFile -Raw | ConvertFrom-Json
      if ($st.protection_scope -eq "global") {{ $scope = "global" }}
    }} catch {{}}
  }}
  $inProject = ((Get-Location).Path).StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)
  if ($scope -ne "global" -and -not $inProject) {{
    & "{real_python}" -m pip @PipArgs
    exit $LASTEXITCODE
  }}
  if ($scope -ne "global" -and -not [string]::IsNullOrWhiteSpace($ExpectedVenv)) {{
    $curVenv = [string]($env:VIRTUAL_ENV)
    if ([string]::IsNullOrWhiteSpace($curVenv) -or (-not $curVenv.Equals($ExpectedVenv, [System.StringComparison]::OrdinalIgnoreCase))) {{
      & "{real_python}" -m pip @PipArgs
      exit $LASTEXITCODE
    }}
  }} elseif ($scope -ne "global") {{
    if ([string]::IsNullOrWhiteSpace([string]($env:VIRTUAL_ENV))) {{
      & "{real_python}" -m pip @PipArgs
      exit $LASTEXITCODE
    }}
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
    pip_cmd = f"""@echo off
setlocal EnableExtensions
("{real_python}" -c "import safedeps" >nul 2>nul) || (
  "{real_python}" -m pip %*
  exit /b %ERRORLEVEL%
)
if /I "%~1"=="uninstall" (
  echo %* | findstr /I /R "\\<safedeps\\>" >nul
  if not errorlevel 1 (
    "{real_python}" -m safedeps.cli guard-cleanup "{str(root)}" >nul 2>nul
    "{real_python}" -m pip %*
    exit /b %ERRORLEVEL%
  )
)
set "_should_guard=0"
if /I "%~1"=="install" (
  set "_should_guard=1"
  set "_scope=project"
  set "_project_root={str(root)}"
  set "_expected_venv={expected_venv}"
  if exist "{str(root / '.safedeps' / 'guard-state.json')}" (
    findstr /I /C:"\"protection_scope\": \"global\"" "{str(root / '.safedeps' / 'guard-state.json')}" >nul
    if not errorlevel 1 set "_scope=global"
  )
  if /I not "%_scope%"=="global" (
    set "_cd=%CD%"
    echo %_cd% | findstr /I /B /C:"%_project_root%" >nul
    if errorlevel 1 set "_should_guard=0"
    if not "%_expected_venv%"=="" (
      if /I "%VIRTUAL_ENV%" NEQ "%_expected_venv%" set "_should_guard=0"
    ) else (
      if "%VIRTUAL_ENV%"=="" set "_should_guard=0"
    )
  )
  if "%_should_guard%"=="1" (
    set "_sdargs=%*"
    echo %_sdargs% | findstr /I /C:"==" >nul
    if errorlevel 1 (
      echo %_sdargs% | findstr /I /C:" -r " /C:" --requirement " /C:"git+" /C:".whl" /C:".tar.gz" /C:".zip" >nul
      if errorlevel 1 (
        echo Blocked: unpinned runtime install is not allowed. Use exact versions ^(example: package==1.2.3^).
        exit /b 2
      )
    )
    set "_sdargs=%*"
    echo %_sdargs% | findstr /I /R "\\<safedeps\\>" >nul
    if not errorlevel 1 (
      if "{official_repo_cmd}"=="" (
        echo Blocked: SafeDeps updates are allowed only from official Git source.
        exit /b 2
      ) else (
        echo %_sdargs% | findstr /I /C:"{official_repo_cmd}" >nul
        if errorlevel 1 (
          echo Blocked: SafeDeps updates are allowed only from official Git source.
          echo Allowed source: {official_repo_cmd}
          exit /b 2
        )
      )
    )
    "{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
    if errorlevel 1 (
      echo SafeDeps blocked pip install due to policy/security findings.
      echo Open UI: safedeps ui . --open-browser
      exit /b 2
    )
  )
)
"{real_python}" -m pip %*
exit /b %ERRORLEVEL%
"""
    npm_wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
if [ "${{1:-}}" = "install" ] || [ "${{1:-}}" = "update" ]; then
  sub="${{1:-}}"
  shift
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
if ($NpmArgs.Length -gt 0) {{
  $cmd = $NpmArgs[0].ToLower()
  if ($cmd -eq "install" -or $cmd -eq "update") {{
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
setlocal
if /I "%~1"=="install" goto :check
if /I "%~1"=="update" goto :check
goto :run
:check
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
if ! "${{REAL_PY}}" -c "import safedeps" >/dev/null 2>&1; then
  exec "${{REAL_PY}}" "$@"
fi
if [ "${{1:-}}" = "-m" ] && [ "${{2:-}}" = "pip" ]; then
  sub="${{3:-}}"
  if [ "$sub" = "install" ] || [ "$sub" = "uninstall" ] || [ "$sub" = "download" ]; then
    if [ "$sub" = "uninstall" ]; then
      ARGS_STR="$*"
      if echo "$ARGS_STR" | grep -Eiq "(^|[[:space:]])safedeps([[:space:]]|$)"; then
        "${{REAL_PY}}" -m safedeps.cli guard-cleanup "$PROJECT_ROOT" >/dev/null 2>&1 || true
        exec "${{REAL_PY}}" "$@"
      fi
    fi
    scope="project"
    if [ -f "$GUARD_STATE_FILE" ] && grep -q '"protection_scope"[[:space:]]*:[[:space:]]*"global"' "$GUARD_STATE_FILE"; then
      scope="global"
    fi
    in_project=0
    case "${{PWD}}/" in
      "${{PROJECT_ROOT}}"/*) in_project=1 ;;
    esac
    if [ "$scope" != "global" ] && [ $in_project -eq 0 ]; then
      exec "${{REAL_PY}}" "$@"
    fi
    if [ "$scope" != "global" ] && [ -n "$EXPECTED_VENV" ]; then
      cur_venv="${{VIRTUAL_ENV:-}}"
      if [ "$cur_venv" != "$EXPECTED_VENV" ]; then
        exec "${{REAL_PY}}" "$@"
      fi
    elif [ "$scope" != "global" ]; then
      # If expected venv was not captured, enforce only when an active venv exists.
      if [ -z "${{VIRTUAL_ENV:-}}" ]; then
        exec "${{REAL_PY}}" "$@"
      fi
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

& "{real_python}" -c "import safedeps" *> $null
if ($LASTEXITCODE -ne 0) {{
  & "{real_python}" @PyArgs
  exit $LASTEXITCODE
}}

if ($PyArgs.Length -ge 3 -and $PyArgs[0] -eq "-m" -and $PyArgs[1].ToLower() -eq "pip" -and $PyArgs[2].ToLower() -eq "uninstall") {{
  $argsLine = [string]::Join(" ", $PyArgs)
  if ($argsLine -match "(^|\\s)safedeps(\\s|$)") {{
    & "{real_python}" -m safedeps.cli guard-cleanup "{str(root)}" *> $null
    & "{real_python}" @PyArgs
    exit $LASTEXITCODE
  }}
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
  $inProject = ((Get-Location).Path).StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)
  if ($scope -ne "global" -and -not $inProject) {{
    & "{real_python}" @PyArgs
    exit $LASTEXITCODE
  }}
  if ($scope -ne "global" -and -not [string]::IsNullOrWhiteSpace($ExpectedVenv)) {{
    $curVenv = [string]($env:VIRTUAL_ENV)
    if ([string]::IsNullOrWhiteSpace($curVenv) -or (-not $curVenv.Equals($ExpectedVenv, [System.StringComparison]::OrdinalIgnoreCase))) {{
      & "{real_python}" @PyArgs
      exit $LASTEXITCODE
    }}
  }} elseif ($scope -ne "global") {{
    if ([string]::IsNullOrWhiteSpace([string]($env:VIRTUAL_ENV))) {{
      & "{real_python}" @PyArgs
      exit $LASTEXITCODE
    }}
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
setlocal EnableExtensions
("{real_python}" -c "import safedeps" >nul 2>nul) || (
  "{real_python}" %*
  exit /b %ERRORLEVEL%
)
if /I "%~1"=="-m" if /I "%~2"=="pip" if /I "%~3"=="uninstall" (
  echo %* | findstr /I /R "\\<safedeps\\>" >nul
  if not errorlevel 1 (
    "{real_python}" -m safedeps.cli guard-cleanup "{str(root)}" >nul 2>nul
    "{real_python}" %*
    exit /b %ERRORLEVEL%
  )
)
set "_should_guard=0"
if /I "%~1"=="-m" if /I "%~2"=="pip" (
  if /I "%~3"=="install" set "_should_guard=1"
  if /I "%~3"=="uninstall" set "_should_guard=1"
  if /I "%~3"=="download" set "_should_guard=1"
  if "%_should_guard%"=="1" (
    set "_scope=project"
    set "_project_root={str(root)}"
    set "_expected_venv={expected_venv}"
    if exist "{str(root / '.safedeps' / 'guard-state.json')}" (
      findstr /I /C:"\"protection_scope\": \"global\"" "{str(root / '.safedeps' / 'guard-state.json')}" >nul
      if not errorlevel 1 set "_scope=global"
    )
    if /I not "%_scope%"=="global" (
      set "_cd=%CD%"
      echo %_cd% | findstr /I /B /C:"%_project_root%" >nul
      if errorlevel 1 set "_should_guard=0"
      if not "%_expected_venv%"=="" (
        if /I "%VIRTUAL_ENV%" NEQ "%_expected_venv%" set "_should_guard=0"
      ) else (
        if "%VIRTUAL_ENV%"=="" set "_should_guard=0"
      )
    )
    if "%_should_guard%"=="1" (
      if /I "%~3"=="install" (
        set "_sdargs=%*"
        echo %_sdargs% | findstr /I /C:"==" >nul
        if errorlevel 1 (
          echo %_sdargs% | findstr /I /C:" -r " /C:" --requirement " /C:"git+" /C:".whl" /C:".tar.gz" /C:".zip" >nul
          if errorlevel 1 (
            echo Blocked: unpinned runtime install is not allowed. Use exact versions ^(example: package==1.2.3^).
            exit /b 2
          )
        )
      )
      if /I "%~3"=="install" (
        set "_sdargs=%*"
        echo %_sdargs% | findstr /I /R "\\<safedeps\\>" >nul
        if not errorlevel 1 (
          if "{official_repo_cmd}"=="" (
            echo Blocked: SafeDeps updates are allowed only from official Git source.
            exit /b 2
          ) else (
            echo %_sdargs% | findstr /I /C:"{official_repo_cmd}" >nul
            if errorlevel 1 (
              echo Blocked: SafeDeps updates are allowed only from official Git source.
              echo Allowed source: {official_repo_cmd}
              exit /b 2
            )
          )
        )
      )
      "{real_python}" -m safedeps.cli scan . --fail-on {fail_on}
      if errorlevel 1 (
        echo SafeDeps blocked python -m pip due to policy/security findings.
        echo Open UI: safedeps ui . --open-browser
        exit /b 2
      )
    )
  )
)
"{real_python}" %*
exit /b %ERRORLEVEL%
"""
    (bindir / "pip.ps1").write_text(pip_ps1, encoding="utf-8")
    (bindir / "pip3.ps1").write_text(pip3_ps1, encoding="utf-8")
    (bindir / "pip.cmd").write_text(pip_cmd, encoding="utf-8")
    (bindir / "pip3.cmd").write_text(pip_cmd, encoding="utf-8")
    (bindir / "npm").write_text(npm_wrapper, encoding="utf-8")
    os.chmod(bindir / "npm", 0o755)
    (bindir / "npm.ps1").write_text(npm_ps1, encoding="utf-8")
    (bindir / "npm.cmd").write_text(npm_cmd, encoding="utf-8")
    (bindir / "python").write_text(python_wrapper, encoding="utf-8")
    (bindir / "python3").write_text(python_wrapper, encoding="utf-8")
    os.chmod(bindir / "python", 0o755)
    os.chmod(bindir / "python3", 0o755)
    (bindir / "python.ps1").write_text(python_ps1, encoding="utf-8")
    (bindir / "python3.ps1").write_text(python_ps1, encoding="utf-8")
    (bindir / "python.cmd").write_text(python_cmd, encoding="utf-8")
    (bindir / "python3.cmd").write_text(python_cmd, encoding="utf-8")

    activate = root / ".safedeps" / "activate.sh"
    activate.write_text(
        "#!/usr/bin/env bash\n"
        'export PATH="$PWD/.safedeps/bin:$PATH"\n'
        'echo "SafeDeps pip guard active for this shell."\n',
        encoding="utf-8",
    )
    os.chmod(activate, 0o755)

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
    print(f"- Guard wrappers: {pip_path} and {pip3_path}")
    _state = _load_guard_state(root)
    if "protection_scope" not in _state or not _state.get("protection_scope"):
        _state["protection_scope"] = default_scope
    auto_guard = bool(_state.get("auto_guard_powershell", False))
    _write_guard_state(root, _state)
    # Hard resync of profile hooks on reinstall/setup with verification.
    try:
        _force_autoguard_resync(root, auto_guard)
    except Exception:
        pass
    print(f"- Protection scope default: {_state['protection_scope']}")
    print(f"- Activate in bash/zsh: source {activate}")
    print(f"- Activate in PowerShell: . {activate_ps1}")
    print("- After activation, pip install is guarded automatically in this project shell/session.")
    return 0

def get_setup_status(root: Path):
    pip_wrapper = root / ".safedeps" / "bin" / "pip"
    activate = root / ".safedeps" / "activate.sh"
    activate_ps1 = root / ".safedeps" / "activate.ps1"
    policy = root / ".safedeps" / "policy.json"
    missing = []
    if not policy.exists():
        missing.append("policy")
    if not pip_wrapper.exists():
        missing.append("pip wrapper")
    if not activate.exists():
        missing.append("activate script")
    if not activate_ps1.exists():
        missing.append("PowerShell activate script")
    if missing:
        return f"Not configured ({', '.join(missing)} missing). Run: safedeps setup ."
    return "Configured. Activate with: source .safedeps/activate.sh (bash) or . .safedeps/activate.ps1 (PowerShell)"

def _guard_state_file(root: Path):
    return root / ".safedeps" / "guard-state.json"

def _powershell_profile_candidates():
    home = Path.home()
    return [
        home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
        home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
    ]

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

def _set_user_path_guard_entry(root: Path, enable: bool):
    guard_bin = str((root / ".safedeps" / "bin").resolve())
    norm_guard = guard_bin.lower()
    if _is_windows():
        entries = _get_user_path_entries_windows()
        filtered = [e for e in entries if str(e).strip().lower() != norm_guard]
        if enable:
            filtered.insert(0, guard_bin)
        ok = _write_user_path_entries_windows(filtered)
    else:
        ok = True
    cur_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    cur_filtered = [e for e in cur_entries if str(e).strip().lower() != norm_guard]
    if enable:
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

def _load_guard_state(root: Path):
    default = {"auto_guard_powershell": False, "protection_scope": "project"}
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
    return out

def _write_guard_state(root: Path, state: dict):
    path = _guard_state_file(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")

def _is_auto_guard_enabled(root: Path):
    return _sync_autoguard_state_file(root)

def _set_powershell_autoguard(root: Path, enable: bool):
    snippet = _guard_profile_snippet(root)
    marker_start = "# >>> SafeDeps Auto Guard >>>"
    marker_end = "# <<< SafeDeps Auto Guard <<<"
    updated_any = False
    candidates = _powershell_profile_candidates()
    for profile in candidates:
        profile.parent.mkdir(parents=True, exist_ok=True)
        content = profile.read_text(encoding="utf-8") if profile.exists() else ""
        if enable:
            if marker_start in content and marker_end in content:
                start = content.find(marker_start)
                end = content.find(marker_end, start)
                if end != -1:
                    end += len(marker_end)
                    if end < len(content) and content[end:end + 1] == "\n":
                        end += 1
                    existing = content[start:end]
                    if existing != snippet:
                        if content and not content.endswith("\n") and start == len(content):
                            content += "\n"
                        content = content[:start] + snippet + content[end:]
                        profile.write_text(content, encoding="utf-8")
                        updated_any = True
                    continue
            if content and not content.endswith("\n"):
                content += "\n"
            content += snippet
            profile.write_text(content, encoding="utf-8")
            updated_any = True
        else:
            if marker_start in content and marker_end in content:
                start = content.find(marker_start)
                end = content.find(marker_end, start)
                if end != -1:
                    end += len(marker_end)
                    if end < len(content) and content[end:end + 1] == "\n":
                        end += 1
                    content = content[:start] + content[end:]
                    profile.write_text(content, encoding="utf-8")
                    updated_any = True
    state = _load_guard_state(root)
    state["auto_guard_powershell"] = enable
    _write_guard_state(root, state)
    _set_user_path_guard_entry(root, enable)
    if enable and not updated_any:
        return "Auto guard already enabled in PowerShell profile."
    if (not enable) and not updated_any:
        return "Auto guard already disabled in PowerShell profile."
    return "Auto guard enabled for new PowerShell sessions." if enable else "Auto guard disabled for new PowerShell sessions."

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

def _path_guard_entry_present(root: Path):
    guard_bin = str((root / ".safedeps" / "bin").resolve()).lower()
    if _is_windows():
        return any(str(e).strip().lower() == guard_bin for e in _get_user_path_entries_windows())
    return any(str(e).strip().lower() == guard_bin for e in os.environ.get("PATH", "").split(os.pathsep) if e)

def _effective_autoguard_enabled(root: Path):
    return _profile_snippet_present(root) or _path_guard_entry_present(root)

def _sync_autoguard_state_file(root: Path):
    effective = _effective_autoguard_enabled(root)
    state = _load_guard_state(root)
    if bool(state.get("auto_guard_powershell", False)) != effective:
        state["auto_guard_powershell"] = effective
        _write_guard_state(root, state)
    return effective

def _verify_autoguard_state(root: Path, expected_enabled: bool):
    state_enabled = bool(_load_guard_state(root).get("auto_guard_powershell", False))
    snippet_present = _profile_snippet_present(root)
    path_present = _path_guard_entry_present(root)
    if expected_enabled:
        return state_enabled and (snippet_present or path_present)
    return (not state_enabled) and (not snippet_present) and (not path_present)

def apply_guard_toggle(root: Path, action: str):
    if action == "enable_auto":
        return _set_powershell_autoguard(root, True)
    if action == "disable_auto":
        return _set_powershell_autoguard(root, False)
    if action == "set_scope_project":
        state = _load_guard_state(root)
        state["protection_scope"] = "project"
        _write_guard_state(root, state)
        return "Protection scope set to PROJECT ONLY (inside this project path)."
    if action == "set_scope_global":
        state = _load_guard_state(root)
        state["protection_scope"] = "global"
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
        return f"Auto-start ON for new PowerShell sessions | Scope: {scope}."
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
