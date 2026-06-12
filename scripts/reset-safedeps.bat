@echo off
setlocal
if "%NO_PAUSE%"=="" set "NO_PAUSE=0"
set "SCRIPT_EXIT=0"

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR%"=="" set "SCRIPT_DIR=%CD%\"

set "PWRSCRIPT=%SCRIPT_DIR%reset-safedeps.ps1"
if not exist "%PWRSCRIPT%" (
  echo Missing script: %PWRSCRIPT%
  exit /b 1
)

if "%~1"=="/?" (
  echo Usage:
  echo   reset-safedeps.bat [project-path]
  echo.
  echo Optional project path removes that project's .safedeps folder.
  echo.
  exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PWRSCRIPT%" %*
if errorlevel 1 set "SCRIPT_EXIT=1"

if "%SCRIPT_EXIT%"=="1" (
  echo.
  echo PowerShell reset ended with errors.
)

echo.
echo Done. Reopen terminal for a clean environment.
if /I not "%NO_PAUSE%"=="1" (
  echo.
  echo Premere un tasto per chiudere...
  pause >nul
)

if "%SCRIPT_EXIT%"=="1" exit /b 1
