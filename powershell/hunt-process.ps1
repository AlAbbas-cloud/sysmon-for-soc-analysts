<#
.SYNOPSIS
    Hunt for suspicious process activity using Sysmon Event IDs 1, 5, 8, 10 and 25.

.DESCRIPTION
    This script parses Sysmon Operational logs and highlights:
        - Suspicious process creations (LOLBINs, odd parents, suspicious paths)
        - PowerShell abuse
        - Process injection indicators (Process Access, CreateRemoteThread, Tampering)
        - Suspicious parent/child relationships
        - Suspicious terminated processes

    Designed to align with hunts described in: process-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== Process Hunt (Sysmon Event IDs 1, 5, 8, 10, 25) ===`n" -ForegroundColor Cyan

# Helper: safely get events
function Get-SysmonEvents {
    param(
        [int[]]$Ids
    )
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

# --- Event ID 1: Process Create ---
Write-Host "[*] Pulling Process Create events (ID 1)..." -ForegroundColor Green
$procEvents = Get-SysmonEvents -Ids 1 | Select-Object TimeCreated, Id, Message

# Parse into structured objects
$processes = foreach ($e in $procEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+CommandLine.*', '')
        CommandLine = ($msg -replace '.*CommandLine:\s+', '' -replace '\s+CurrentDirectory.*', '')
        ParentImage = ($msg -replace '.*ParentImage:\s+', '' -replace '\s+ParentCommandLine.*', '')
        ParentCmd   = ($msg -replace '.*ParentCommandLine:\s+', '' -replace '\s+User.*', '')
        User        = ($msg -replace '.*User:\s+', '' -replace '\s+LogonGuid.*', '')
        PID         = ($msg -replace '.*ProcessId:\s+', '' -replace '\s+Image.*', '')
    }
}

if (-not $processes) {
    Write-Host "No process creation events found." -ForegroundColor Yellow
} else {
    # Suspicious LOLBINs
    $lolbins = 'rundll32.exe','regsvr32.exe','mshta.exe','wmic.exe','bitsadmin.exe','certutil.exe','powershell.exe','cmd.exe'
    $susLolbins = $processes | Where-Object {
        $exe = ($_ .Image | Split-Path -Leaf)
        $lolbins -contains $exe
    }

    # Suspicious paths (temp/appdata)
    $susPaths = $processes | Where-Object {
        $_.Image -match '\\AppData\\|\\Temp\\|\\ProgramData\\'
    }

    # Suspicious parent/child combos (Office/Browser -> PowerShell/cmd)
    $officeParents = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe'
    $browserParents = 'chrome.exe','msedge.exe','iexplore.exe'
    $susParentChild = $processes | Where-Object {
        $child = ($_ .Image | Split-Path -Leaf)
        $parent = ($_ .ParentImage | Split-Path -Leaf)
        (
            ($officeParents -contains $parent -and $child -match 'powershell.exe|cmd.exe') -or
            ($browserParents -contains $parent -and $child -match 'powershell.exe|cmd.exe')
        )
    }

    # PowerShell abuse (encoded, hidden, etc.)
    $psAbuse = $processes | Where-Object {
        ($_ .Image -match 'powershell.exe') -and
        ($_.CommandLine -match '-enc|-encodedcommand|-nop|-noprofile|-w hidden|-windowstyle hidden|FromBase64String|Invoke-Expression|IEX')
    }

    Write-Host "`n--- Suspicious LOLBIN Executions (Event ID 1) ---" -ForegroundColor Magenta
    $susLolbins | Sort-Object TimeCreated | Select-Object TimeCreated, Image, CommandLine, ParentImage | Format-Table -AutoSize

    Write-Host "`n--- Suspicious Process Paths (Temp/AppData/ProgramData) (Event ID 1) ---" -ForegroundColor Magenta
    $susPaths | Sort-Object TimeCreated | Select-Object TimeCreated, Image, CommandLine, ParentImage | Format-Table -AutoSize

    Write-Host "`n--- Suspicious Parent/Child (Office/Browser -> PowerShell/cmd) (Event ID 1) ---" -ForegroundColor Magenta
    $susParentChild | Sort-Object TimeCreated | Select-Object TimeCreated, ParentImage, Image, CommandLine | Format-Table -AutoSize

    Write-Host "`n--- PowerShell Abuse (Encoded/Hidden/Obfuscated) (Event ID 1) ---" -ForegroundColor Magenta
    $psAbuse | Sort-Object TimeCreated | Select-Object TimeCreated, Image, CommandLine, ParentImage | Format-Table -AutoSize
}

# --- Event ID 10: Process Access ---
Write-Host "`n[*] Pulling Process Access events (ID 10)..." -ForegroundColor Green
$accessEvents = Get-SysmonEvents -Ids 10 | Select-Object TimeCreated, Id, Message

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
$accessToHighValue | Sort-Object TimeCreated | Select-Object TimeCreated, SourceImage, TargetImage, GrantedAccess | Format-Table -AutoSize

# --- Event ID 8: CreateRemoteThread ---
Write-Host "`n[*] Pulling CreateRemoteThread events (ID 8)..." -ForegroundColor Green
$crtEvents = Get-SysmonEvents -Ids 8 | Select-Object TimeCreated, Id, Message

$remoteThreads = foreach ($e in $crtEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        SourceImage = ($msg -replace '.*SourceImage:\s+', '' -replace '\s+TargetImage.*', '')
        TargetImage = ($msg -replace '.*TargetImage:\s+', '' -replace '\s+NewThreadId.*', '')
    }
}

Write-Host "`n--- Remote Thread Creation (Event ID 8) ---" -ForegroundColor Magenta
$remoteThreads | Sort-Object TimeCreated | Select-Object TimeCreated, SourceImage, TargetImage | Format-Table -AutoSize

# --- Event ID 25: Process Tampering ---
Write-Host "`n[*] Pulling Process Tampering events (ID 25)..." -ForegroundColor Green
$tampEvents = Get-SysmonEvents -Ids 25 | Select-Object TimeCreated, Id, Message

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
$procTamper | Sort-Object TimeCreated | Select-Object TimeCreated, SourceImage, TargetImage, Type | Format-Table -AutoSize

# --- Event ID 5: Process Terminated ---
Write-Host "`n[*] Pulling Process Terminated events (ID 5)..." -ForegroundColor Green
$termEvents = Get-SysmonEvents -Ids 5 | Select-Object TimeCreated, Id, Message

$terminated = foreach ($e in $termEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Image       = ($msg -replace '.*Image:\s+', '' -replace '\s+ProcessId.*', '')
        PID         = ($msg -replace '.*ProcessId:\s+', '' -replace '\s+User.*', '')
        User        = ($msg -replace '.*User:\s+', '' -replace '\s+LogonGuid.*', '')
    }
}

# Heuristic: short-lived processes (seen in ID 1 and quickly in ID 5)
$pidToStart = @{}
foreach ($p in $processes) {
    if ($p.PID -and -not $pidToStart.ContainsKey($p.PID)) {
        $pidToStart[$p.PID] = $p.TimeCreated
    }
}

$shortLived = foreach ($t in $terminated) {
    if ($pidToStart.ContainsKey($t.PID)) {
        $lifetime = $t.TimeCreated - $pidToStart[$t.PID]
        if ($lifetime.TotalSeconds -lt 10) {
            [PSCustomObject]@{
                TimeCreated = $t.TimeCreated
                Image       = $t.Image
                PID         = $t.PID
                User        = $t.User
                LifetimeSec = [math]::Round($lifetime.TotalSeconds,2)
            }
        }
    }
}

Write-Host "`n--- Short-Lived / Suspicious Terminated Processes (Event ID 5 + 1) ---" -ForegroundColor Magenta
$shortLived | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`nProcess Hunt Complete.`n" -ForegroundColor Cyan

