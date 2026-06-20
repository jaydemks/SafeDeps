@echo off
setlocal EnableExtensions

set "PROJECT=%RUNNER_TEMP%\safedeps-cmd-pip-e2e"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
python -m safedeps.cli setup . --fail-on HIGH --install-scope system --protection-scope project
call .safedeps\activate.bat
call pip install six
if %ERRORLEVEL% EQU 0 (
  echo Expected unpinned pip install to be blocked.
  exit /b 1
)
call pip install six==1.17.0
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

set "PROJECT=%RUNNER_TEMP%\safedeps-cmd-requirements-e2e"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
echo six>requirements.txt
python -m safedeps.cli setup . --fail-on HIGH --install-scope system --protection-scope project
call .safedeps\activate.bat
call pip install -r requirements.txt
if %ERRORLEVEL% EQU 0 (
  echo Expected unpinned requirements install to be blocked.
  exit /b 1
)
echo six==1.17.0>requirements.txt
call pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%

set "PROJECT=%RUNNER_TEMP%\safedeps-cmd-constraints-e2e"
mkdir "%PROJECT%"
cd /d "%PROJECT%"
echo urllib3>constraints.txt
python -m safedeps.cli setup . --fail-on HIGH --install-scope system --protection-scope project
call .safedeps\activate.bat
call pip install -c constraints.txt six==1.17.0
if %ERRORLEVEL% EQU 0 (
  echo Expected unpinned constraints install to be blocked.
  exit /b 1
)
echo urllib3==2.2.3>constraints.txt
call pip install -c constraints.txt six==1.17.0
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
