$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false
$BasePath = $env:PATH

function New-GuardedNpmProject {
    param([Parameter(Mandatory=$true)][string]$Name)
    Write-Host "::group::activate $Name"
    $env:PATH = $BasePath
    $project = Join-Path $env:RUNNER_TEMP $Name
    New-Item -ItemType Directory -Force -Path $project | Out-Null
    Set-Location $project
    npm init -y
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m safedeps.cli setup . --install-scope system --protection-scope project
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    . .\.safedeps\activate.ps1
    Get-Command npm | Select-Object -ExpandProperty Source
    Write-Host "::endgroup::"
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

function Write-ExactLodashManifest {
    @'
{
  "name": "safedeps-npm-runtime",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21"
  }
}
'@ | Set-Content -Path package.json -Encoding utf8
}

Write-Host "::group::test_unpinned_install_policy"
try {
    New-GuardedNpmProject "safedeps-npm-runtime-install" | Out-Null
    Invoke-ExpectBlocked "Expected unpinned npm install to be blocked." { npm install lodash }
    npm install lodash@4.17.21 --save-exact --ignore-scripts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_package_lock_policy"
try {
    New-GuardedNpmProject "safedeps-npm-runtime-lockfile" | Out-Null
    Write-ExactLodashManifest
    npm install --package-lock-only --ignore-scripts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (-not (Test-Path package-lock.json)) {
        Write-Error "Expected package-lock.json to be created."
        exit 1
    }
    python -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_update_policy"
try {
    New-GuardedNpmProject "safedeps-npm-runtime-update" | Out-Null
    Write-ExactLodashManifest
    npm install --package-lock-only --ignore-scripts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Invoke-ExpectBlocked "Expected unpinned npm update to be blocked." { npm update lodash }
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_lifecycle_script_policy"
try {
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
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_uninstall_policy"
try {
    New-GuardedNpmProject "safedeps-npm-runtime-uninstall" | Out-Null
    Write-ExactLodashManifest
    npm install --ignore-scripts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Invoke-ExpectBlocked "Expected npm uninstall to be blocked by scan policy." { npm uninstall lodash }
} finally {
    Write-Host "::endgroup::"
}
