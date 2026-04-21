<#
.SYNOPSIS
    Hunt for process injection, memory tampering, and stealthy execution
    using Sysmon Event IDs 8, 9, 10, 25, and 7.

.DESCRIPTION
    This script highlights:
        - Process Access (Event ID 10)
        - Remote Thread Creation (Event ID 8)
        - Process Tampering (Event ID 25)
        - Suspicious DLL loads (Event ID 7)
        - RawAccessRead (Event ID 9)
        - LSASS access attempts
        - Injection chains (10 → 8 → 25 → 7)

    Designed to align with hunts described in: injection-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== Injection Hunt (Sysmon Event IDs 8, 9, 10, 25, 7) ===`n" -ForegroundColor Cyan

function Get-SysmonEvents {
    param([int[]]$Ids)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

# -------------------------------
# Event ID 10 — Process Access
# -------------------------------
Write-Host "[*] Pulling Process Access events (ID 10)..." -ForegroundColor Green
$accessEvents = Get-SysmonEvents -Ids 10 | Select-Object TimeCreated, Message

$procAccess = foreach ($e in $accessEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated   = $e.TimeCreated
        SourceImage   = ($msg -replace '.*SourceImage:\s+', '' -replace '\s+TargetImage.*', '')
        TargetImage   = ($msg -replace '.*TargetImage:\s+', '' -replace '\s+GrantedAccess.*', '')
        GrantedAccess = ($msg -replace '.*GrantedAccess:\s+', '' -replace '\s+CallTrace.*', '')
    }
}

$highValueTargets = 'lsass.exe','winlogon.exe','services.exe','explorer.exe'
$accessToHighValue = $procAccess | Where-Object {
    $target = ($_ .TargetImage | Split-Path -Leaf)
    $highValueTargets -contains $target
}

Write-Host "`n--- Process Access to High-Value Targets (Event ID 10) ---" -ForegroundColor Magenta
$accessToHighValue | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Event ID 8 — CreateRemoteThread
# -------------------------------
Write-Host "`n[*] Pulling CreateRemoteThread events (ID 8)..." -ForegroundColor Green
$crtEvents = Get-SysmonEvents -Ids 8 | Select-Object TimeCreated, Message

$remoteThreads = foreach ($e in $crtEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        SourceImage = ($msg -replace '.*SourceImage:\s+', '' -replace '\s+TargetImage.*', '')
        TargetImage = ($msg -replace '.*TargetImage:\s+', '' -replace '\s+NewThreadId.*', '')
    }
}

Write-Host "`n--- Remote Thread Creation (Event ID 8) ---" -ForegroundColor Magenta
$remoteThreads | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Event ID 25 — Process Tampering
# -------------------------------
Write-Host "`n[*] Pulling Process Tampering events (ID 25)..." -ForegroundColor Green
$tampEvents = Get-SysmonEvents -Ids 25 | Select-Object TimeCreated, Message

$procTamper = foreach ($e in $tampEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        SourceImage = ($msg -replace '.*SourceImage:\s+', '' -replace '\s+TargetImage.*', '')
        TargetImage = ($msg -replace '.*TargetImage:\s+', '' -replace '\s+Type.*', '')
        Type        = ($msg -replace '.*Type:\s+', '' -replace '\s+Status.*', '')
    }
}

Write-Host "`n--- Process Tampering (Event ID 25) ---" -ForegroundColor Magenta
$procTamper | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Event ID 7 — Image Loaded (DLL Loads)
# -------------------------------
Write-Host "`n[*] Pulling Image Loaded events (ID 7)..." -ForegroundColor Green
$imgEvents = Get-SysmonEvents -Ids 7 | Select-Object TimeCreated, Message

$dllLoads = foreach ($e in $imgEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+ImageLoaded.*', '')
        DLL         = ($msg -replace '.*ImageLoaded:\s+', '' -replace '\s+Hashes.*', '')
    }
}

# Suspicious DLL locations
$susDLLs = $dllLoads | Where-Object {
    $_.DLL -match '\\Temp\\|\\AppData\\|\\ProgramData\\'
}

Write-Host "`n--- Suspicious DLL Loads (Event ID 7) ---" -ForegroundColor Magenta
$susDLLs | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Event ID 9 — RawAccessRead
# -------------------------------
Write-Host "`n[*] Pulling RawAccessRead events (ID 9)..." -ForegroundColor Green
$rawEvents = Get-SysmonEvents -Ids 9 | Select-Object TimeCreated, Message

$rawReads = foreach ($e in $rawEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+Device.*', '')
        Device      = ($msg -replace '.*Device:\s+', '' -replace '\s+CallTrace.*', '')
    }
}

Write-Host "`n--- RawAccessRead (Event ID 9) ---" -ForegroundColor Magenta
$rawReads | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# LSASS Access Detection
# -------------------------------
Write-Host "`n--- LSASS Access Attempts (Credential Theft Indicators) ---" -ForegroundColor Magenta
$lsassHits = $procAccess | Where-Object {
    ($_ .TargetImage | Split-Path -Leaf) -eq 'lsass.exe'
}

$lsassHits | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Injection Chain Detection
# -------------------------------
Write-Host "`n--- Injection Chains (10 → 8 → 25 → 7) ---" -ForegroundColor Magenta

$chains = foreach ($access in $procAccess) {
    $src = $access.SourceImage

    $crt = $remoteThreads | Where-Object { $_.SourceImage -eq $src }
    $tam = $procTamper     | Where-Object { $_.SourceImage -eq $src }
    $dll = $susDLLs        | Where-Object { $_.Image -eq $src }

    if ($crt -or $tam -or $dll) {
        [PSCustomObject]@{
            SourceImage = $src
            Access      = $true
            RemoteThread= $crt.Count
            Tampering   = $tam.Count
            DLLLoads    = $dll.Count
        }
    }
}

$chains | Sort-Object SourceImage | Format-Table -AutoSize

Write-Host "`nInjection Hunt Complete.`n" -ForegroundColor Cyan

