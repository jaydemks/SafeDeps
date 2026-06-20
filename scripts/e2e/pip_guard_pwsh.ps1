$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

function New-GuardedProject {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$Scope = "project"
    )
    $project = Join-Path $env:RUNNER_TEMP $Name
    New-Item -ItemType Directory -Force -Path $project | Out-Null
    Set-Location $project
    python -m safedeps.cli setup . --fail-on HIGH --install-scope system --protection-scope $Scope
    . .\.safedeps\activate.ps1
    return $project
}

function Invoke-ExpectBlocked {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )
    $global:LASTEXITCODE = 0
    & $Command
    if ($LASTEXITCODE -eq 0) {
        Write-Error $Message
        exit 1
    }
}

New-GuardedProject "safedeps-pip-e2e" | Out-Null
Invoke-ExpectBlocked "Expected unpinned pip install to be blocked." { pip install six }
pip install six==1.17.0
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-GuardedProject "safedeps-requirements-e2e" | Out-Null
"six" | Set-Content -Path requirements.txt
Invoke-ExpectBlocked "Expected unpinned requirements install to be blocked." { pip install -r requirements.txt }
"six==1.17.0" | Set-Content -Path requirements.txt
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-GuardedProject "safedeps-constraints-e2e" | Out-Null
"urllib3" | Set-Content -Path constraints.txt
Invoke-ExpectBlocked "Expected unpinned constraints install to be blocked." { pip install -c constraints.txt six==1.17.0 }
"urllib3==2.2.3" | Set-Content -Path constraints.txt
pip install -c constraints.txt six==1.17.0
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$project = New-GuardedProject "safedeps-python-m-pip-e2e"
$script = Join-Path $env:RUNNER_TEMP "safedeps-python-m-pip-bypass.ps1"
@'
. .\.safedeps\activate.ps1
python -m pip install six
exit $LASTEXITCODE
'@ | Set-Content -Path $script -Encoding utf8
$child = Start-Process -FilePath "pwsh" -ArgumentList @("-NoProfile", "-File", $script) -WorkingDirectory $project -Wait -PassThru -NoNewWindow
if ($child.ExitCode -eq 0) {
    Write-Error "Expected unpinned python -m pip install to be blocked."
    exit 1
}

$project = New-GuardedProject "safedeps-project-scope-e2e"
$outside = Join-Path $env:RUNNER_TEMP "safedeps-project-scope-outside"
New-Item -ItemType Directory -Force -Path $outside | Out-Null
Set-Location $outside
pip install six==1.17.0
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
