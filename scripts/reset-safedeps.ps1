param(
    [string]$ProjectPath = "",
    [switch]$KeepProjectConfig
)

$ErrorActionPreference = "Stop"

function Remove-SafedepsEntriesFromPath([string]$pathValue) {
    if ([string]::IsNullOrWhiteSpace($pathValue)) {
        return ""
    }
    $parts = $pathValue -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $filtered = @()
    $seen = @{}
    foreach ($part in $parts) {
        $normalized = $part.ToLowerInvariant().Replace("/", "\")
        if ($normalized -match '(^|\\)\\.safedeps\\bin(\\.*)?$' -or $normalized -match '(^|\\)\\.safedeps\\bin(\\.*)?;') {
            continue
        }
        if ($seen.ContainsKey($normalized)) {
            continue
        }
        $seen[$normalized] = $true
        $filtered += $part
    }
    return [string]::Join(";", $filtered)
}

function Remove-SafedepsProfileMarkers([string]$pathValue) {
    if (-not (Test-Path $pathValue)) {
        return
    }
    $raw = Get-Content $pathValue -Raw
    $raw = [regex]::Replace(
        $raw,
        '(?si)# >>> SafeDeps Auto Guard >>>.*?# <<< SafeDeps Auto Guard <<<\r?\n?',
        '',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $lines = $raw -split "`r?`n"
    $clean = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match '(?i)\\.safedeps[\\/ ]?bin' -or $line -match '(?i)SafeDeps Auto Guard') {
            continue
        }
        if ($line.Trim() -ne "" -or $clean.Count -gt 0) {
            $clean.Add($line)
        }
    }
    $result = ($clean | Where-Object { $_ -ne $null }) -join [Environment]::NewLine
    $result = $result.TrimEnd([Environment]::NewLine.ToCharArray())
    Set-Content -Path $pathValue -Value $result -Encoding UTF8
}

function Remove-SafedepsCmdAutoRun {
    $keyPath = "HKCU:\Software\Microsoft\Command Processor"
    if (-not (Test-Path $keyPath)) {
        return
    }
    try {
        $current = (Get-ItemProperty -Path $keyPath -Name AutoRun -ErrorAction SilentlyContinue).AutoRun
        if ([string]::IsNullOrWhiteSpace($current)) {
            return
        }
        $oldPattern = '(?is)(\s*&\s*)?rem >>> SafeDeps Auto Guard >>>.*?rem <<< SafeDeps Auto Guard <<<(\s*&\s*)?'
        $newPattern = '(?is)(\s*&\s*)?if\s+"SafeDeps Auto Guard"=="SafeDeps Auto Guard"\s+if\s+exist\s+".*?\.safedeps[\\/]activate\.bat"\s+call\s+".*?\.safedeps[\\/]activate\.bat"(\s*&\s*)?'
        $clean = [regex]::Replace($current, $oldPattern, ' & ')
        $clean = [regex]::Replace($clean, $newPattern, ' & ')
        $clean = [regex]::Replace($clean, '(\s*&\s*){2,}', ' & ').Trim()
        $clean = [regex]::Replace($clean, '^&\s*|\s*&$', '').Trim()
        if ([string]::IsNullOrWhiteSpace($clean)) {
            Remove-ItemProperty -Path $keyPath -Name AutoRun -ErrorAction SilentlyContinue
            Write-Host "Removed CMD AutoRun SafeDeps hook."
        }
        elseif ($clean -ne $current) {
            Set-ItemProperty -Path $keyPath -Name AutoRun -Value $clean
            Write-Host "Cleaned CMD AutoRun SafeDeps hook."
        }
    }
    catch {
        Write-Host "Warning: cannot clean CMD AutoRun. $_"
    }
}

function Remove-SafedepsProjectState([string]$root) {
    if ([string]::IsNullOrWhiteSpace($root)) {
        return
    }
    $resolved = $null
    try {
        $resolved = Resolve-Path $root -ErrorAction Stop
    }
    catch {
        Write-Host "Invalid project path: $root"
        return
    }
    $projectSafeDeps = Join-Path $resolved.Path ".safedeps"
    if (Test-Path $projectSafeDeps) {
        Remove-Item -Recurse -Force $projectSafeDeps
        Write-Host "Removed: $projectSafeDeps"
    }
}

function Invoke-SafeDepsProcessStop([int]$pid, [string]$label) {
    try {
        Stop-Process -Id $pid -Force -ErrorAction Stop
        Write-Host "Stopped $label process: $pid"
    }
    catch {
        Write-Host "Warning: cannot stop $label process $pid. $_"
    }
}

function Stop-SafedepsUiServers {
    try {
        $uiProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -and (
                $_.CommandLine -match 'safedeps\s+ui\b' -or
                    $_.CommandLine -match 'safedeps\.exe' -or
                    $_.CommandLine -match 'safedeps\.cli\s+ui\b' -or
                    $_.CommandLine -match 'python.*safedeps\.cli\s+ui\b' -or
                    $_.CommandLine -match 'python.*\s-m\s+safedeps\.cli\s+ui\b'
                )
            }
        foreach ($proc in $uiProcs) {
            Invoke-SafeDepsProcessStop -pid $proc.ProcessId -label "UI"
        }
    }
    catch {
        Write-Host "Warning: UI process sweep failed. $_"
    }
}

function Stop-SafedepsPortListeners {
    param([int]$Port = 5200)

    $pids = @()
    try {
        $listeners = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq "Listen" -and $_.LocalPort -eq $Port }
        foreach ($listener in $listeners) {
            if ($listener.OwningProcess -and -not ($pids -contains $listener.OwningProcess)) {
                $pids += [int]$listener.OwningProcess
            }
        }
    }
    catch {
        $raw = netstat -ano -p tcp 2>$null | Select-String -Pattern "LISTENING"
        foreach ($line in $raw) {
            $parts = ($line -split "\\s+") | Where-Object { $_ }
            if ($parts.Count -lt 5) {
                continue
            }
            if ($parts[1] -notmatch "([\\[]?[0-9a-fA-F:\\.]+[\\]]?|\\d+\\.\\d+\\.\\d+\\.\\d+):$Port\\b") {
                continue
            }
            $pid = [int]$parts[$parts.Count - 1]
            if ($pid -gt 0 -and -not ($pids -contains $pid)) {
                $pids += $pid
            }
        }
    }

    foreach ($pid in $pids) {
        Invoke-SafeDepsProcessStop -pid $pid -label "port-$Port"
    }
}

$profilePaths = @(
    Join-Path $HOME "Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    Join-Path $HOME "Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
)

try {
    if ($env:PATH) {
        $env:PATH = Remove-SafedepsEntriesFromPath $env:PATH
    }

    $pathScopes = @(
        "Process",
        "User",
        "Machine"
    )
    foreach ($scope in $pathScopes) {
        $current = [Environment]::GetEnvironmentVariable("Path", $scope)
        if ($null -ne $current) {
            $clean = Remove-SafedepsEntriesFromPath $current
            if ($clean -ne $current) {
                [Environment]::SetEnvironmentVariable("Path", $clean, $scope)
                Write-Host "Cleaned PATH entries in $scope environment scope."
            }
        }
    }
}
catch {
    Write-Host "Warning: failed to update some PATH scopes. $_"
}

foreach ($profile in $profilePaths) {
    if (Test-Path $profile) {
        try {
            Remove-SafedepsProfileMarkers $profile
            Write-Host "Cleaned profile: $profile"
        }
        catch {
            Write-Host "Warning: cannot clean profile $profile. $_"
        }
    }
}

Remove-SafedepsCmdAutoRun

Stop-SafedepsUiServers
Stop-SafedepsPortListeners -Port 5200

if (Test-Path (Join-Path $HOME ".safedeps")) {
    Remove-Item -Recurse -Force (Join-Path $HOME ".safedeps")
    Write-Host "Removed: $HOME\.safedeps"
}

try {
    $listeners = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Listen" -and $_.LocalPort -eq 5200 }
    if ($listeners) {
        Write-Host "Port 5200 still active by:"
        $listeners | Select-Object -First 5 -Property LocalAddress, LocalPort, OwningProcess, State | Format-Table -AutoSize | Out-Host
        Write-Host "Tip: close these processes or restart shell/PC if stale."
    } else {
        Write-Host "Port 5200 is not currently in LISTEN state."
    }
}
catch {
    Write-Host "Warning: unable to query TCP listeners on port 5200. $_"
}

if (-not $KeepProjectConfig -and -not [string]::IsNullOrWhiteSpace($ProjectPath)) {
    Remove-SafedepsProjectState $ProjectPath
}

Remove-Item Function:\pip -ErrorAction SilentlyContinue
Remove-Item Function:\pip3 -ErrorAction SilentlyContinue
Remove-Item Function:\python -ErrorAction SilentlyContinue
Remove-Item Function:\python3 -ErrorAction SilentlyContinue
Remove-Item Function:\npm -ErrorAction SilentlyContinue
Remove-Item Alias:\pip -ErrorAction SilentlyContinue
Remove-Item Alias:\pip3 -ErrorAction SilentlyContinue
Remove-Item Alias:\python -ErrorAction SilentlyContinue
Remove-Item Alias:\python3 -ErrorAction SilentlyContinue
Remove-Item Alias:\npm -ErrorAction SilentlyContinue

Write-Host "SafeDeps environment reset completed."
Write-Host "Run: $env:COMSPEC /k for a fresh shell, then:"
Write-Host "where.exe pip"
Write-Host "where.exe python"
Write-Host "where.exe safedeps"
if (-not $KeepProjectConfig) {
  Write-Host ""
  Write-Host "Premi INVIO per chiudere..."
  Read-Host | Out-Null
}
