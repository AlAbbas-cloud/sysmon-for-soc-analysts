<#
.SYNOPSIS
    Hunt for suspicious registry activity using Sysmon Event IDs 12, 13, and 14.

.DESCRIPTION
    This script highlights:
        - Autorun / Run key persistence
        - Service creation / modification
        - Malware-style config keys
        - Security / evasion-related registry changes
        - Registry key renaming (stealth persistence)
        - Timestomping-style registry activity (via volume of changes)

    Designed to align with hunts described in: registry-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== Registry Hunt (Sysmon Event IDs 12, 13, 14) ===`n" -ForegroundColor Cyan

function Get-SysmonEvents {
    param([int[]]$Ids)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

Write-Host "[*] Pulling Registry events (IDs 12, 13, 14)..." -ForegroundColor Green
$regEvents = Get-SysmonEvents -Ids 12,13,14 | Select-Object TimeCreated, Id, Message

$registry = foreach ($e in $regEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        EventID     = $e.Id
        TargetObject= ($msg -replace '.*TargetObject:\s+', '' -replace '\s+Details.*', '')
        Details     = ($msg -replace '.*Details:\s+', '' -replace '\s+NewName.*', '')
        NewName     = ($msg -replace '.*NewName:\s+', '' -replace '\s+.*', '')
    }
}

if (-not $registry) {
    Write-Host "No registry events found." -ForegroundColor Yellow
    return
}

# -------------------------------
# 1. Autorun Persistence (Run / RunOnce)
# -------------------------------
$autorunPaths = @(
    "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "RunOnce","RunServices","RunServicesOnce"
)

$autoruns = $registry | Where-Object {
    $autorunPaths | ForEach-Object { $_ -and ($_.TargetObject -like "*$_*") }
}

Write-Host "`n--- Autorun / Run Key Persistence (IDs 12, 13) ---" -ForegroundColor Magenta
$autoruns | Sort-Object TimeCreated | Format-Table TimeCreated,EventID,TargetObject,Details -AutoSize

# -------------------------------
# 2. Service Creation / Modification
# -------------------------------
$services = $registry | Where-Object {
    $_.TargetObject -like "*SYSTEM\\CurrentControlSet\\Services*"
}

Write-Host "`n--- Service Creation / Modification (IDs 12, 13) ---" -ForegroundColor Magenta
$services | Sort-Object TimeCreated | Format-Table TimeCreated,EventID,TargetObject,Details -AutoSize

# -------------------------------
# 3. Malware-Style Configuration Keys
# -------------------------------
$malwareConfig = $registry | Where-Object {
    $_.TargetObject -like "*HKCU\Software\Microsoft\*" -or
    $_.TargetObject -like "*HKCU\Software\*" -or
    $_.TargetObject -like "*HKLM\Software\*"
} | Where-Object {
    $_.TargetObject -match '\

\[A-Za-z0-9]{6,}\\' -or $_.Details -match '[A-Za-z0-9+/]{20,}={0,2}'
}

Write-Host "`n--- Suspicious Malware-Style Registry Config (ID 13/14) ---" -ForegroundColor Magenta
$malwareConfig | Sort-Object TimeCreated | Format-Table TimeCreated,EventID,TargetObject,Details -AutoSize

# -------------------------------
# 4. Security / Evasion-Related Keys
# -------------------------------
$securityKeywords = @(
    "Windows Defender","Security Center","Policies","Audit","Amsi","TamperProtection",
    "DisableAntiSpyware","DisableRealtimeMonitoring","DisableBehaviorMonitoring"
)

$securityChanges = $registry | Where-Object {
    $securityKeywords | ForEach-Object { $_ -and ($_.TargetObject -like "*$_*") }
}

Write-Host "`n--- Security / Evasion-Related Registry Changes ---" -ForegroundColor Magenta
$securityChanges | Sort-Object TimeCreated | Format-Table TimeCreated,EventID,TargetObject,Details -AutoSize

# -------------------------------
# 5. Registry Key Renaming (Stealth Persistence)
# -------------------------------
$keyRenames = $registry | Where-Object {
    $_.EventID -eq 14 -and $_.NewName -ne ''
}

Write-Host "`n--- Registry Key Renaming (Event ID 14) ---" -ForegroundColor Magenta
$keyRenames | Sort-Object TimeCreated | Format-Table TimeCreated,TargetObject,NewName -AutoSize

# -------------------------------
# 6. High-Volume Registry Activity (Timestomping / Noise)
# -------------------------------
$byKey = $registry | Group-Object TargetObject | Where-Object { $_.Count -gt 5 }

Write-Host "`n--- High-Volume Registry Activity (Same Key Modified Repeatedly) ---" -ForegroundColor Magenta
$byKey | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "`nRegistry Hunt Complete.`n" -ForegroundColor Cyan
