<#
.SYNOPSIS
    Hunt for persistence mechanisms using Sysmon Event IDs:
    2, 4, 11, 12, 13, 14, 16, 19, 20, 21.

.DESCRIPTION
    This script highlights:
        - Registry Run Key persistence
        - Startup folder persistence
        - WMI event subscription persistence
        - Service-based persistence
        - DLL hijacking indicators
        - Sysmon tampering attempts

    Designed to align with hunts described in: persistence-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== Persistence Hunt (Sysmon Event IDs 2, 4, 11, 12, 13, 14, 16, 19, 20, 21) ===`n" -ForegroundColor Cyan

function Get-SysmonEvents {
    param([int[]]$Ids)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

# -------------------------------
# Registry Persistence (12, 13, 14)
# -------------------------------
Write-Host "[*] Pulling Registry persistence events (IDs 12, 13, 14)..." -ForegroundColor Green
$regEvents = Get-SysmonEvents -Ids 12,13,14 | Select-Object TimeCreated, Id, Message

$registry = foreach ($e in $regEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        EventID     = $e.Id
        Key         = ($msg -replace '.*TargetObject:\s+', '' -replace '\s+Details.*', '')
        Details     = ($msg -replace '.*Details:\s+', '' -replace '\s+NewName.*', '')
    }
}

# Autorun keys
$autorunPaths = @(
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "RunOnce","RunServices","RunServicesOnce"
)

$autoruns = $registry | Where-Object {
    $autorunPaths | ForEach-Object { $_ -and ($_.Key -like "*$_*") }
}

Write-Host "`n--- Registry Run Key Persistence (IDs 12, 13, 14) ---" -ForegroundColor Magenta
$autoruns | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Startup Folder Persistence (11 + 2)
# -------------------------------
Write-Host "`n[*] Pulling File Create events (ID 11)..." -ForegroundColor Green
$fileEvents = Get-SysmonEvents -Ids 11 | Select-Object TimeCreated, Message

$startupFiles = foreach ($e in $fileEvents) {
    $msg = $e.Message

    $path = ($msg -replace '.*TargetFilename:\s+', '' -replace '\s+CreationUtcTime.*', '')

    if ($path -match 'Startup') {
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            File        = $path
        }
    }
}

Write-Host "`n--- Startup Folder Persistence (ID 11) ---" -ForegroundColor Magenta
$startupFiles | Sort-Object TimeCreated | Format-Table -AutoSize

# Timestomping (ID 2)
Write-Host "`n[*] Pulling File Creation Time Changed events (ID 2)..." -ForegroundColor Green
$timestomp = Get-SysmonEvents -Ids 2 | Select-Object TimeCreated, Message

$timestompParsed = foreach ($e in $timestomp) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        File        = ($msg -replace '.*TargetFilename:\s+', '' -replace '\s+CreationUtcTime.*', '')
    }
}

Write-Host "`n--- File Timestomping (ID 2) ---" -ForegroundColor Magenta
$timestompParsed | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# WMI Persistence (19, 20, 21)
# -------------------------------
Write-Host "`n[*] Pulling WMI persistence events (IDs 19, 20, 21)..." -ForegroundColor Green
$wmiEvents = Get-SysmonEvents -Ids 19,20,21 | Select-Object TimeCreated, Id, Message

$wmiParsed = foreach ($e in $wmiEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        EventID     = $e.Id
        Details     = $msg
    }
}

Write-Host "`n--- WMI Persistence (IDs 19, 20, 21) ---" -ForegroundColor Magenta
$wmiParsed | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Service-Based Persistence (12, 13)
# -------------------------------
Write-Host "`n[*] Detecting Service-based persistence..." -ForegroundColor Green
$services = $registry | Where-Object {
    $_.Key -like "*SYSTEM\\CurrentControlSet\\Services*"
}

Write-Host "`n--- Service-Based Persistence (IDs 12, 13) ---" -ForegroundColor Magenta
$services | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# DLL Hijacking (7 + 11)
# -------------------------------
Write-Host "`n[*] Pulling DLL load events (ID 7)..." -ForegroundColor Green
$dllEvents = Get-SysmonEvents -Ids 7 | Select-Object TimeCreated, Message

$dllLoads = foreach ($e in $dllEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+ImageLoaded.*', '')
        DLL         = ($msg -replace '.*ImageLoaded:\s+', '' -replace '\s+Hashes.*', '')
    }
}

$susDLLs = $dllLoads | Where-Object {
    $_.DLL -match '\\Temp\\|\\AppData\\|\\ProgramData\\'
}

Write-Host "`n--- DLL Hijacking Indicators (ID 7) ---" -ForegroundColor Magenta
$susDLLs | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Sysmon Tampering (4, 16)
# -------------------------------
Write-Host "`n[*] Pulling Sysmon tampering events (IDs 4, 16)..." -ForegroundColor Green
$sysmonTamper = Get-SysmonEvents -Ids 4,16 | Select-Object TimeCreated, Id, Message

Write-Host "`n--- Sysmon Tampering (IDs 4, 16) ---" -ForegroundColor Magenta
$sysmonTamper | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`nPersistence Hunt Complete.`n" -ForegroundColor Cyan

