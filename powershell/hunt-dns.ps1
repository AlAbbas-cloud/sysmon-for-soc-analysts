<#
.SYNOPSIS
    Hunt for suspicious DNS activity using Sysmon Event ID 22.

.DESCRIPTION
    This script parses Sysmon DNS Query events (Event ID 22) and highlights:
        - High-entropy domains (possible DGA)
        - Long or suspicious subdomains
        - DNS tunneling patterns
        - DNS queries from unusual parent processes
        - DNS requests to dynamic DNS providers
        - DNS requests from system processes (possible injection)

    Designed for SOC analysts performing DNS-based threat hunting.

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n=== DNS Hunt (Sysmon Event ID 22) ===`n" -ForegroundColor Cyan

# Pull Sysmon DNS events
$dnsEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id      = 22
} | Select-Object TimeCreated, Id, Message

if (-not $dnsEvents) {
    Write-Host "No DNS events found." -ForegroundColor Yellow
    return
}

# Parse events into structured objects
$parsed = foreach ($event in $dnsEvents) {
    $msg = $event.Message

    [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Process     = ($msg -replace '.*ProcessName:\s+', '' -replace '\s+QueryName.*', '')
        Query       = ($msg -replace '.*QueryName:\s+', '' -replace '\s+QueryStatus.*', '')
        PID         = ($msg -replace '.*ProcessId:\s+', '' -replace '\s+QueryName.*', '')
    }
}

# Detection patterns
$dynamicDNS = @(
    "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "dynu.net"
)

Write-Host "Analyzing DNS queries..." -ForegroundColor Green

# 1. High-entropy / random-looking domains
$highEntropy = $parsed | Where-Object {
    $_.Query.Length -gt 40 -or $_.Query -match '[0-9a-zA-Z]{20,}'
}

# 2. DNS tunneling indicators
$dnsTunneling = $parsed | Where-Object {
    $_.Query -match '\.' -and ($_.Query.Split('.').Count -gt 5)
}

# 3. Dynamic DNS usage
$ddnsHits = $parsed | Where-Object {
    $dynamicDNS | ForEach-Object { $_.Query -like "*$_" }
}

# 4. Suspicious parent processes
$suspiciousParents = $parsed | Where-Object {
    $_.Process -match 'rundll32|regsvr32|mshta|wmic|powershell|cmd'
}

# 5. System processes making DNS requests
$systemDNS = $parsed | Where-Object {
    $_.Process -match 'lsass|winlogon|services|svchost'
}

# Output results
Write-Host "`n--- High Entropy / DGA-like Domains ---" -ForegroundColor Magenta
$highEntropy | Format-Table -AutoSize

Write-Host "`n--- DNS Tunneling Indicators ---" -ForegroundColor Magenta
$dnsTunneling | Format-Table -AutoSize

Write-Host "`n--- Dynamic DNS Providers ---" -ForegroundColor Magenta
$ddnsHits | Format-Table -AutoSize

Write-Host "`n--- Suspicious Parent Processes ---" -ForegroundColor Magenta
$suspiciousParents | Format-Table -AutoSize

Write-Host "`n--- System Processes Performing DNS Lookups ---" -ForegroundColor Magenta
$systemDNS | Format-Table -AutoSize

Write-Host "`nDNS Hunt Complete.`n" -ForegroundColor Cyan
