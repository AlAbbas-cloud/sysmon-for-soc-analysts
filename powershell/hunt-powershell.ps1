<#
.SYNOPSIS
    Hunt for suspicious PowerShell activity using Sysmon telemetry.

.DESCRIPTION
    This script highlights:
        - Encoded / obfuscated PowerShell
        - Download cradles
        - Office → PowerShell execution
        - AMSI / logging bypass attempts
        - PowerShell-based lateral movement
        - LOLBIN-chained PowerShell execution

    Designed to align with hunts described in: powershell-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== PowerShell Hunt (Sysmon Event IDs 1, 3, 7, 10, 22) ===`n" -ForegroundColor Cyan

function Get-SysmonEvents {
    param([int[]]$Ids)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

# -------------------------------
# Event ID 1 — Process Create
# -------------------------------
Write-Host "[*] Pulling Process Create events (ID 1)..." -ForegroundColor Green
$procEvents = Get-SysmonEvents -Ids 1 | Select-Object TimeCreated, Message

$processes = foreach ($e in $procEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+CommandLine.*', '')
        CommandLine = ($msg -replace '.*CommandLine:\s+', '' -replace '\s+CurrentDirectory.*', '')
        ParentImage = ($msg -replace '.*ParentImage:\s+', '' -replace '\s+ParentCommandLine.*', '')
        ParentCmd   = ($msg -replace '.*ParentCommandLine:\s+', '' -replace '\s+User.*', '')
    }
}

# -------------------------------
# Encoded / Obfuscated PowerShell
# -------------------------------
$encodedPS = $processes | Where-Object {
    $_.Image -match 'powershell.exe' -and
    $_.CommandLine -match '-enc|-encodedcommand|-nop|-noprofile|-w hidden|-windowstyle hidden|FromBase64String|Invoke-Expression|IEX'
}

Write-Host "`n--- Encoded / Obfuscated PowerShell ---" -ForegroundColor Magenta
$encodedPS | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# PowerShell Download Cradles
# -------------------------------
$downloadPS = $processes | Where-Object {
    $_.Image -match 'powershell.exe' -and
    $_.CommandLine -match 'Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|http|https'
}

Write-Host "`n--- PowerShell Download Cradles ---" -ForegroundColor Magenta
$downloadPS | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Office → PowerShell Execution
# -------------------------------
$officeParents = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe'
$browserParents = 'chrome.exe','msedge.exe','iexplore.exe'

$officePS = $processes | Where-Object {
    ($officeParents -contains ($_.ParentImage | Split-Path -Leaf)) -and
    ($_.Image -match 'powershell.exe')
}

$browserPS = $processes | Where-Object {
    ($browserParents -contains ($_.ParentImage | Split-Path -Leaf)) -and
    ($_.Image -match 'powershell.exe')
}

Write-Host "`n--- Office → PowerShell Execution ---" -ForegroundColor Magenta
$officePS | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n--- Browser → PowerShell Execution ---" -ForegroundColor Magenta
$browserPS | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# AMSI / Logging Bypass
# -------------------------------
$amsiPS = $processes | Where-Object {
    $_.Image -match 'powershell.exe' -and
    $_.CommandLine -match 'AmsiUtils|amsiInitFailed|Add-Type|Reflection|Bypass'
}

Write-Host "`n--- AMSI / Logging Bypass Attempts ---" -ForegroundColor Magenta
$amsiPS | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# Event ID 3 — Network Connections
# -------------------------------
Write-Host "[*] Pulling Network Connection events (ID 3)..." -ForegroundColor Green
$netEvents = Get-SysmonEvents -Ids 3 | Select-Object TimeCreated, Message

$connections = foreach ($e in $netEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+User.*', '')
        DestIP      = ($msg -replace '.*DestinationIp:\s+', '' -replace '\s+DestinationHostname.*', '')
        DestPort    = ($msg -replace '.*DestinationPort:\s+', '' -replace '\s+Protocol.*', '')
    }
}

$psConnections = $connections | Where-Object {
    $_.Image -match 'powershell.exe'
}

Write-Host "`n--- PowerShell Network Connections ---" -ForegroundColor Magenta
$psConnections | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# PowerShell Lateral Movement
# -------------------------------
$lateralPS = $processes | Where-Object {
    $_.Image -match 'powershell.exe' -and
    $_.CommandLine -match 'Invoke-Command|Enter-PSSession|New-PSSession|WinRM'
}

Write-Host "`n--- PowerShell Lateral Movement ---" -ForegroundColor Magenta
$lateralPS | Sort-Object TimeCreated | Format-Table -AutoSize

# -------------------------------
# LOLBIN → PowerShell
# -------------------------------
$lolbins = 'rundll32.exe','regsvr32.exe','mshta.exe','wmic.exe','certutil.exe'

$lolbinPS = $processes | Where-Object {
    $parent = ($_.ParentImage | Split-Path -Leaf)
    ($lolbins -contains $parent) -and
    ($_.Image -match 'powershell.exe')
}

Write-Host "`n--- LOLBIN → PowerShell Execution ---" -ForegroundColor Magenta
$lolbinPS | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`nPowerShell Hunt Complete.`n" -ForegroundColor Cyan
