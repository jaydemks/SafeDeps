$ErrorActionPreference = "Continue"
$PSNativeCommandUseErrorActionPreference = $false

function New-ConsoleProject {
    param([Parameter(Mandatory=$true)][string]$Name)
    $project = Join-Path $env:RUNNER_TEMP $Name
    if (Test-Path $project) { Remove-Item -Recurse -Force $project }
    New-Item -ItemType Directory -Force -Path $project | Out-Null
    Set-Location $project
    dotnet new console --framework net8.0 --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Invoke-ExpectScanBlocked {
    param([Parameter(Mandatory=$true)][string]$Message)
    python -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
    if ($LASTEXITCODE -eq 0) {
        Write-Error $Message
        exit 1
    }
    $global:LASTEXITCODE = 0
}

Write-Host "::group::test_dotnet_add_pinned_package"
try {
    New-ConsoleProject "safedeps-nuget-add-pinned"
    dotnet add package Newtonsoft.Json --version 13.0.3 --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_dotnet_add_floating_package"
try {
    New-ConsoleProject "safedeps-nuget-add-floating"
    dotnet add package Newtonsoft.Json --version "[13.0.1,14.0.0)" --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Invoke-ExpectScanBlocked "Expected floating NuGet PackageReference scan to fail."
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_untrusted_nuget_source_config"
try {
    New-ConsoleProject "safedeps-nuget-untrusted-source"
    @'
<configuration>
  <packageSources>
    <clear />
    <add key="evil" value="https://evil.example/v3/index.json" />
  </packageSources>
</configuration>
'@ | Set-Content -Path NuGet.Config -Encoding utf8
    Invoke-ExpectScanBlocked "Expected untrusted NuGet source scan to fail."
} finally {
    Write-Host "::endgroup::"
}

Write-Host "::group::test_restore_lockfile_policy"
try {
    New-ConsoleProject "safedeps-nuget-restore-lockfile"
    dotnet add package Newtonsoft.Json --version 13.0.3 --no-restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet restore --use-lock-file --source https://api.nuget.org/v3/index.json
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (-not (Test-Path packages.lock.json)) {
        Write-Error "Expected packages.lock.json to be created."
        exit 1
    }
    python -m safedeps.cli scan . --fail-on HIGH --out security-artifacts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Write-Host "::endgroup::"
}

exit 0
