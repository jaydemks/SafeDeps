$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

function New-GuardedNpmProject {
    param([Parameter(Mandatory=$true)][string]$Name)
    $project = Join-Path $env:RUNNER_TEMP $Name
    New-Item -ItemType Directory -Force -Path $project | Out-Null
    Set-Location $project
    npm init -y
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m safedeps.cli setup . --install-scope system --protection-scope project
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    . .\.safedeps\activate.ps1
    return $project
}

function Invoke-ExpectBlocked {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )
    & $Command
    if ($LASTEXITCODE -eq 0) {
        Write-Error $Message
        exit 1
    }
}

New-GuardedNpmProject "safedeps-npm-runtime-install" | Out-Null
Invoke-ExpectBlocked "Expected unpinned npm install to be blocked." { npm install lodash }
npm install lodash@4.17.21 --ignore-scripts
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-GuardedNpmProject "safedeps-npm-runtime-lifecycle" | Out-Null
@'
{
  "name": "safedeps-npm-runtime-lifecycle",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node postinstall.js"
  },
  "dependencies": {
    "lodash": "4.17.21"
  }
}
'@ | Set-Content -Path package.json -Encoding utf8
Invoke-ExpectBlocked "Expected npm install script project to be blocked." { npm install --package-lock-only }

New-GuardedNpmProject "safedeps-npm-runtime-uninstall" | Out-Null
npm install lodash@4.17.21 --ignore-scripts
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Invoke-ExpectBlocked "Expected npm uninstall to be blocked by scan policy." { npm uninstall lodash }
