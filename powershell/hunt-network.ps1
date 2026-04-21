<#
.SYNOPSIS
    Hunt for suspicious network activity using Sysmon Event IDs 3 and 22.

.DESCRIPTION
    This script highlights:
        - Suspicious outbound connections
        - Beaconing behaviour
        - Non-standard ports
        - Dynamic DNS usage
        - DNS tunneling indicators
        - Lateral movement ports
        - Network activity from suspicious processes

    Designed to align with hunts described in: network-hunts.md

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== Network Hunt (Sysmon Event IDs 3 & 22) ===`n" -ForegroundColor Cyan

# Helper function
function Get-SysmonEvents {
    param([int[]]$Ids)
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id      = $Ids
    } -ErrorAction SilentlyContinue
}

# --- Event ID 3: Network Connections ---
Write-Host "[*] Pulling Network Connection events (ID 3)..." -ForegroundColor Green
$netEvents = Get-SysmonEvents -Ids 3 | Select-Object TimeCreated, Id, Message

$connections = foreach ($e in $netEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        SourceImage = ($msg -replace '.*Image:\s+', '' -replace '\s+User.*', '')
        SourceIP    = ($msg -replace '.*SourceIp:\s+', '' -replace '\s+SourceHostname.*', '')
        SourcePort  = ($msg -replace '.*SourcePort:\s+', '' -replace '\s+DestinationIp.*', '')
        DestIP      = ($msg -replace '.*DestinationIp:\s+', '' -replace '\s+DestinationHostname.*', '')
        DestPort    = ($msg -replace '.*DestinationPort:\s+', '' -replace '\s+Protocol.*', '')
        Protocol    = ($msg -replace '.*Protocol:\s+', '' -replace '\s+Initiated.*', '')
    }
}

# --- Event ID 22: DNS Queries ---
Write-Host "[*] Pulling DNS Query events (ID 22)..." -ForegroundColor Green
$dnsEvents = Get-SysmonEvents -Ids 22 | Select-Object TimeCreated, Id, Message

$dns = foreach ($e in $dnsEvents) {
    $msg = $e.Message

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Process     = ($msg -replace '.*ProcessName:\s+', '' -replace '\s+QueryName.*', '')
        Query       = ($msg -replace '.*QueryName:\s+', '' -replace '\s+QueryStatus.*', '')
    }
}

# --- Detection Logic ---

# 1. Suspicious outbound connections
$rarePorts = $connections | Where-Object { $_.DestPort -notin 80,443,53,3389,445,22 }

# 2. Beaconing (repeated connections to same IP)
$beaconing = $connections |
    Group-Object DestIP |
    Where-Object { $_.Count -gt 10 } |
    Select-Object Name, Count

# 3. Dynamic DNS usage
$dynamicDNS = @("duckdns.org","no-ip.com","ddns.net","hopto.org","dynu.net")
$ddnsHits = $dns | Where-Object {
    $dynamicDNS | ForEach-Object { $_.Query -like "*$_" }
}

# 4. DNS tunneling indicators
$dnsTunneling = $dns | Where-Object {
    $_.Query -match '\.' -and ($_.Query.Split('.').Count -gt 5)
}

# 5. Suspicious processes making network connections
$suspiciousProcs = $connections | Where-Object {
    $_.SourceImage -match 'rundll32|regsvr32|mshta|wmic|powershell|cmd|wscript'
}

# 6. Lateral movement ports
$lateralPorts = $connections | Where-Object {
    $_.DestPort -in 445,3389,5985,5986,135
}

# --- Output ---

Write-Host "`n--- Suspicious Outbound Connections (Non-standard Ports) ---" -ForegroundColor Magenta
$rarePorts | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n--- Possible Beaconing Behaviour (Repeated Destinations) ---" -ForegroundColor Magenta
$beaconing | Format-Table -AutoSize

Write-Host "`n--- Dynamic DNS Usage ---" -ForegroundColor Magenta
$ddnsHits | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n--- DNS Tunneling Indicators ---" -ForegroundColor Magenta
$dnsTunneling | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n--- Suspicious Processes Making Network Connections ---" -ForegroundColor Magenta
$suspiciousProcs | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`n--- Lateral Movement Ports (445, 3389, 5985, 5986, 135) ---" -ForegroundColor Magenta
$lateralPorts | Sort-Object TimeCreated | Format-Table -AutoSize

Write-Host "`nNetwork Hunt Complete.`n" -ForegroundColor Cyan

