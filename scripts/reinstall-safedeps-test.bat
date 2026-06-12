@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
if not defined SCRIPT_DIR set "SCRIPT_DIR=%CD%"

set "PROJECT_PATH=%~1"
if not defined PROJECT_PATH set "PROJECT_PATH=%SCRIPT_DIR%\.."
set "SYSTEM_PYTHON=%~2"
set "VENV_PATH=%~3"
if not defined VENV_PATH set "VENV_PATH=.venv-test"
if not defined NO_PAUSE set "NO_PAUSE=0"
if not defined SKIP_VENV set "SKIP_VENV=0"

if not exist "%PROJECT_PATH%\pyproject.toml" if not exist "%PROJECT_PATH%\setup.py" (
  if exist "%SCRIPT_DIR%\..\pyproject.toml" set "PROJECT_PATH=%SCRIPT_DIR%\.."
  if exist "%SCRIPT_DIR%\..\setup.py" set "PROJECT_PATH=%SCRIPT_DIR%\.."
)

if not exist "%PROJECT_PATH%" (
  echo ERROR: project path not found: %PROJECT_PATH%
  goto :err_exit
)

if not exist "%PROJECT_PATH%\pyproject.toml" if not exist "%PROJECT_PATH%\setup.py" (
  echo ERROR: not a python project path: %PROJECT_PATH%
  echo Missing pyproject.toml or setup.py.
  goto :err_exit
)

pushd "%PROJECT_PATH%"

set "RES_PY="

call :probe_python "%SYSTEM_PYTHON%" explicit
if defined RES_PY goto :py_done

call :probe_python "%VENV_PATH%\Scripts\python.exe" venv
if defined RES_PY goto :py_done

call :probe_python "%USERPROFILE%\AppData\Local\Programs\Python\Python311\python.exe" user-311
if defined RES_PY goto :py_done

call :probe_python "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" local-311
if defined RES_PY goto :py_done

for /f "delims=" %%p in ('where python 2^>nul') do (
  echo %%~p | findstr /I /C:"\\WindowsApps\\python.exe" >nul
  if errorlevel 1 (
    call :probe_python "%%~p" path
    if defined RES_PY goto :py_done
  )
)
for /f "delims=" %%p in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
  call :probe_python "%%~p" py
  if defined RES_PY goto :py_done
)

:py_done
if not defined RES_PY (
  echo ERROR: no usable system Python found with pip module.
  goto :err_exit
)

set "SYSTEM_PYTHON=%RES_PY%"
echo Using system python: %SYSTEM_PYTHON%
set "RES_PY="

echo 1) System install: uninstall + editable reinstall
"%SYSTEM_PYTHON%" -m pip uninstall safedeps -y
if errorlevel 1 echo (safedeps non era installato nel context system)
"%SYSTEM_PYTHON%" -m pip install -e .
if errorlevel 1 (
  echo ERROR: system editable install failed.
  goto :err_exit
)

if /I not "%SKIP_VENV%"=="1" (
  if exist "%VENV_PATH%\Scripts\python.exe" (
    set "VENV_PY=%VENV_PATH%\Scripts\python.exe"
  ) else if exist "%VENV_PATH%\bin\python" (
    set "VENV_PY=%VENV_PATH%\bin\python"
  ) else (
    set "VENV_PY="
  )

  if not defined VENV_PY (
    echo WARN: virtualenv not found at "%VENV_PATH%" (skipping local install).
  ) else (
    echo 2) Local .venv install: uninstall + editable reinstall
    "%VENV_PY%" -m pip uninstall safedeps -y
    if errorlevel 1 echo (safedeps non era installato nel venv)
    "%VENV_PY%" -m pip install -e .
    if errorlevel 1 (
      echo ERROR: local venv editable install failed.
      goto :err_exit
    )
  )
)

echo 3) Recreate SafeDeps wrappers in project
"%SYSTEM_PYTHON%" -m safedeps.cli setup .
if errorlevel 1 (
  echo ERROR: safedeps.cli setup failed.
  goto :err_exit
)

if exist ".safedeps\bin\pip" (
  echo Setup wrappers:
  "%SYSTEM_PYTHON%" -c "import json, pathlib; p = pathlib.Path('.safedeps/guard-state.json'); print(p.exists() and json.loads(p.read_text()).get('protection_scope'))"
) else (
  echo WARN: wrappers not found under .safedeps/bin
)

echo 4) Checks from current shell
where.exe pip
where.exe python
where.exe safedeps
"%SYSTEM_PYTHON%" -m safedeps.cli --version
"%SYSTEM_PYTHON%" -m pip --version

echo.
echo Tip: open UI with:
echo "%SYSTEM_PYTHON%" -m safedeps.cli ui . --open-browser
goto :good_exit

:probe_python
set "cand=%~1"
set "label=%~2"
if not exist "%cand%" goto :eof
if "%cand:~-4%"==".bat" (
  "%cand%" --version >nul 2>nul
) else (
  "%cand%" -c "import sys" >nul 2>nul
)
if errorlevel 1 goto :eof
"%cand%" -m pip --version >nul 2>nul
if errorlevel 1 goto :eof
set "RES_PY=%cand%"
exit /b 0

:err_exit
set "BATCH_ERR=1"
goto :finally

:good_exit
set "BATCH_ERR=0"
goto :finally

:finally
popd
if /I not "%NO_PAUSE%"=="1" (
  echo.
  if "%BATCH_ERR%"=="0" (
    echo Eseguito correttamente. Premere un tasto per chiudere...
  ) else (
    echo Eseguito con errori. Premere un tasto per chiudere...
  )
  pause >nul
)
if "%BATCH_ERR%"=="1" exit /b 1
exit /b 0
