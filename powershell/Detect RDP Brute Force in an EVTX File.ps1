# Load failed logon events (4625) from an EVTX file
$events = Get-WinEvent -Path ".\Security.evtx" -FilterXPath "*[System/EventID=4625]"

$parsed = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()

    [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Username    = $xml.Event.EventData.Data[5].'#text'
        IPAddress   = $xml.Event.EventData.Data[19].'#text'
        LogonType   = $xml.Event.EventData.Data[10].'#text'
        FailureReason = $xml.Event.EventData.Data[7].'#text'
    }
}

# Filter for RDP brute force (LogonType 10)
$rdpFails = $parsed | Where-Object { $_.LogonType -eq "10" -and $_.IPAddress -ne $null }

# Group by attacking IP
$rdpFails | Group-Object IPAddress | Sort-Object Count -Descending |
    Select-Object Count, Name
