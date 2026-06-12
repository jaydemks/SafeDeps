param(
    [string]$ProjectPath = "",
    [string]$SystemPython = "",
    [string]$VenvPath = ".venv-test",
    [switch]$SkipVenv,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$script:ExitCode = 0

try {
  if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
    $ProjectPath = (Get-Location).Path
  }

  $ProjectPath = (Resolve-Path $ProjectPath).Path
  Set-Location $ProjectPath

  function Test-PythonCandidate([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path)) {
      return $false
    }
    & "$path" -c "import sys" > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
      return $false
    }
    & "$path" -m pip --version > $null 2>&1
    return ($LASTEXITCODE -eq 0)
  }

  function Resolve-SafedepsPython([string]$hint) {
    $candidates = @()

    if (-not [string]::IsNullOrWhiteSpace($hint)) {
      $candidates += $hint
    }

    $envCandidates = @(
      (Join-Path $HOME "AppData\Local\Programs\Python\Python311\python.exe"),
      (Join-Path $HOME "AppData\Local\Programs\Python\Python312\python.exe"),
      (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
      (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python312\python.exe")
    )
    $candidates += $envCandidates

    if (Get-Command py -ErrorAction SilentlyContinue) {
      try {
        $pyPath = (& py -3 -c "import sys; print(sys.executable)")
        if ($pyPath) { $candidates += $pyPath.Trim() }
      }
      catch { }
    }

    $pythonFromPath = Get-Command python -ErrorAction SilentlyContinue | ForEach-Object {
      $_.Source
    } | Where-Object { $_ } | Select-Object -Unique
    $candidates += $pythonFromPath

    foreach ($candidate in $candidates) {
      if (-not (Test-PythonCandidate $candidate)) {
        continue
      }
      $resolved = (Resolve-Path $candidate -ErrorAction SilentlyContinue).Path
      if ($resolved -and ($resolved -notmatch "\\WindowsApps\\python\\.exe$|\\WindowsApps\\python3\\.exe$")) {
        return $resolved
      }
    }
    return ""
  }

  $SystemPythonPath = Resolve-SafedepsPython $SystemPython
  if ([string]::IsNullOrWhiteSpace($SystemPythonPath)) {
    throw "No usable Python interpreter found. Set -SystemPython to a valid python executable."
  }

  # Reset in-memory wrappers/functions that can hijack commands in the current shell.
  Remove-Item Alias:pip -ErrorAction SilentlyContinue
  Remove-Item Alias:pip3 -ErrorAction SilentlyContinue
  Remove-Item Alias:python -ErrorAction SilentlyContinue
  Remove-Item Alias:python3 -ErrorAction SilentlyContinue
  Remove-Item Alias:npm -ErrorAction SilentlyContinue
  Remove-Item Function:\pip -ErrorAction SilentlyContinue
  Remove-Item Function:\pip3 -ErrorAction SilentlyContinue
  Remove-Item Function:\python -ErrorAction SilentlyContinue
  Remove-Item Function:\python3 -ErrorAction SilentlyContinue
  Remove-Item Function:\npm -ErrorAction SilentlyContinue

  Write-Host "1) System install: uninstall + editable reinstall"
  & "$SystemPythonPath" -m pip uninstall safedeps -y
  & "$SystemPythonPath" -m pip install -e .

  if (-not $SkipVenv) {
    $VenvPython = Join-Path (Resolve-Path $ProjectPath) "$VenvPath\Scripts\python.exe"
    if (-not (Test-Path $VenvPython)) {
      throw "Virtualenv python not found: $VenvPython"
    }
    Write-Host "2) Local .venv install: uninstall + editable reinstall"
    & $VenvPython -m pip uninstall safedeps -y
    & $VenvPython -m pip install -e .
  }

  Write-Host "3) Recreate SafeDeps wrappers in project"
  & "$SystemPythonPath" -m safedeps.cli setup .
  . ".\\.safedeps\\activate.ps1"

  Write-Host "4) Checks from current shell"
  where.exe pip
  where.exe python
  where.exe safedeps
  & "$SystemPythonPath" -m safedeps.cli --version
  & "$SystemPythonPath" -m pip --version
  & "$SystemPythonPath" -m pip show safedeps | Out-Host

  Write-Host "System python: $SystemPythonPath"
  Write-Host "Project path: $ProjectPath"
  Write-Host "Venv path: $ProjectPath\\$VenvPath"

  Write-Host ""
  Write-Host "Tip: open UI with:"
  Write-Host "& `"$SystemPythonPath`" -m safedeps.cli ui . --open-browser"
}
catch {
  Write-Host "Error: $($_.Exception.Message)"
  $script:ExitCode = 1
}
finally {
  if (-not $NoPause) {
    Write-Host ""
    Write-Host "Premi INVIO per chiudere..."
    Read-Host | Out-Null
  }

  if ($script:ExitCode -ne 0) {
    exit 1
  }
}
