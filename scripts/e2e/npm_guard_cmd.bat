@echo off
setlocal EnableExtensions

set "PROJECT=%RUNNER_TEMP%\safedeps-npm-runtime-install"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
call npm init -y
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
python -m safedeps.cli setup . --install-scope system --protection-scope project
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
call .safedeps\activate.bat
call npm install lodash
if %ERRORLEVEL% EQU 0 (
  echo Expected unpinned npm install to be blocked.
  exit /b 1
)
call npm install lodash@4.17.21 --ignore-scripts
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

set "PROJECT=%RUNNER_TEMP%\safedeps-npm-runtime-lifecycle"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
call npm init -y
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
python -m safedeps.cli setup . --install-scope system --protection-scope project
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
call .safedeps\activate.bat
(
  echo {
  echo   "name": "safedeps-npm-runtime-lifecycle",
  echo   "version": "1.0.0",
  echo   "scripts": {
  echo     "postinstall": "node postinstall.js"
  echo   },
  echo   "dependencies": {
  echo     "lodash": "4.17.21"
  echo   }
  echo }
) > package.json
call npm install --package-lock-only
if %ERRORLEVEL% EQU 0 (
  echo Expected npm install script project to be blocked.
  exit /b 1
)

set "PROJECT=%RUNNER_TEMP%\safedeps-npm-runtime-uninstall"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
call npm init -y
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
python -m safedeps.cli setup . --install-scope system --protection-scope project
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
call .safedeps\activate.bat
call npm install lodash@4.17.21 --ignore-scripts
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
call npm uninstall lodash
if %ERRORLEVEL% EQU 0 (
  echo Expected npm uninstall to be blocked by scan policy.
  exit /b 1
)
