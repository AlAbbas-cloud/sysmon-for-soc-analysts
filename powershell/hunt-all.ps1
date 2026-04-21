<#
.SYNOPSIS
    Master hunting script that runs ALL Sysmon-based hunts.

.DESCRIPTION
    This script sequentially executes:
        - hunt-process.ps1
        - hunt-network.ps1
        - hunt-dns.ps1
        - hunt-registry.ps1
        - hunt-injection.ps1
        - hunt-persistence.ps1
        - hunt-powershell.ps1

    It provides a full SOC-grade threat hunting sweep using Sysmon telemetry.

.NOTES
    Author: Ali Abbas
    Repo: sysmon-for-soc-analysts
#>

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "      Sysmon Hunt Suite — FULL RUN" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

# Helper: run a module safely
function Run-HuntModule {
    param(
        [string]$Name,
        [string]$Path
    )

    Write-Host "`n>>> Running $Name ...`n" -ForegroundColor Yellow

    if (Test-Path $Path) {
        try {
            & $Path
        }
        catch {
            Write-Host "Error running $Name: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "$Name not found at path: $Path" -ForegroundColor DarkYellow
    }

    Write-Host "`n--- Completed: $Name ---`n" -ForegroundColor Green
}

# Paths (relative to repo structure)
$base = Split-Path -Parent $MyInvocation.MyCommand.Path

$modules = @(
    @{ Name = "Process Hunt";      File = "$base\hunt-process.ps1" },
    @{ Name = "Network Hunt";      File = "$base\hunt-network.ps1" },
    @{ Name = "DNS Hunt";          File = "$base\hunt-dns.ps1" },
    @{ Name = "Registry Hunt";     File = "$base\hunt-registry.ps1" },
    @{ Name = "Injection Hunt";    File = "$base\hunt-injection.ps1" },
    @{ Name = "Persistence Hunt";  File = "$base\hunt-persistence.ps1" },
    @{ Name = "PowerShell Hunt";   File = "$base\hunt-powershell.ps1" }
)

foreach ($m in $modules) {
    Run-HuntModule -Name $m.Name -Path $m.File
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "   Sysmon Hunt Suite — FULL RUN COMPLETE" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

