# DNS Hunts (Sysmon Event ID 22)

This section provides practical, SOC‑focused hunting workflows for detecting suspicious or malicious DNS activity using Sysmon telemetry.  
DNS is one of the most abused channels for C2, exfiltration, staging, and evasion — and Sysmon Event ID 22 gives analysts deep visibility into which processes are making DNS requests.

Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: High‑Entropy or Random‑Looking Domains (DGA)

## What to Look For
Domains that appear:
- Random  
- Long  
- High‑entropy  
- Algorithmically generated  

Examples:
- `ajd92j1kda9s0d.biz`
- `xj3k-29dk-ff02.info`

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**

## Why It Matters
DGAs are used by:
- Botnets  
- Malware families (Emotet, Qakbot, TrickBot)  
- C2 frameworks  

## Investigation Steps
1. Check the **process** making the DNS request.  
2. Look for **repeated failed lookups** (common in DGAs).  
3. Pivot to **Network Connections** (Event ID 3).  
4. Review **Process Create** (Event ID 1).  
5. Check for **file creation** (Event ID 11) for payload staging.

---

# 2. Hunt: DNS Tunneling (Data Exfiltration)

## What to Look For
- Very long DNS queries  
- TXT record lookups  
- High volume of DNS requests  
- Subdomains with encoded data  

Examples:
- `aHR0cHM6Ly9...attacker.com`
- `chunk1.chunk2.chunk3.domain.com`

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**

## Why It Matters
DNS tunneling is used for:
- Data exfiltration  
- Covert C2  
- Firewall evasion  

## Investigation Steps
1. Look for **TXT** or **NULL** record types.  
2. Check for **high request frequency**.  
3. Pivot to **Network Connections** (Event ID 3).  
4. Review **Process Access** (Event ID 10) for injection.  
5. Investigate **registry persistence** (Event ID 13).

---

# 3. Hunt: DNS Requests from Suspicious Processes

## What to Look For
Processes that normally should NOT perform DNS lookups:

Examples:
- `rundll32.exe`
- `regsvr32.exe`
- `mshta.exe`
- `wmic.exe`
- `powershell.exe` with encoded commands

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**
- **Event ID 1 — Process Create**

## Why It Matters
Malware often uses LOLBINs to hide network activity.

## Investigation Steps
1. Identify the **parent process**.  
2. Check the **command line** for suspicious arguments.  
3. Pivot to **Image Loaded** (Event ID 7) for AMSI bypass DLLs.  
4. Review **file creation** (Event ID 11).  
5. Investigate **WMI persistence** (Event IDs 19–21).

---

# 4. Hunt: DNS Requests to Newly Registered Domains

## What to Look For
Domains that:
- Are newly created  
- Have no reputation  
- Are associated with malware campaigns  

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**

## Why It Matters
Attackers frequently use:
- Newly registered domains  
- Disposable infrastructure  
- Fast‑flux DNS  

## Investigation Steps
1. Check domain age using OSINT (VirusTotal, whois).  
2. Pivot to **Network Connections** (Event ID 3).  
3. Review **Process Create** (Event ID 1).  
4. Look for **file drops** (Event ID 11).  
5. Investigate **registry changes** (Event ID 13).

---

# 5. Hunt: DNS Requests to Dynamic DNS Providers

## What to Look For
Domains ending in:
- `duckdns.org`
- `no-ip.com`
- `ddns.net`
- `hopto.org`

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**

## Why It Matters
Dynamic DNS is commonly used for:
- C2  
- Malware staging  
- Botnet control  

## Investigation Steps
1. Identify the **process** making the request.  
2. Check for **encoded PowerShell**.  
3. Pivot to **Process Access** (Event ID 10).  
4. Review **network connections** (Event ID 3).  
5. Investigate **persistence** (Event ID 13 or WMI events).

---

# 6. Hunt: DNS Requests from System Processes

## What to Look For
System processes performing DNS lookups unexpectedly:

Examples:
- `lsass.exe`
- `winlogon.exe`
- `services.exe`
- `svchost.exe` (unusual service groups)

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**
- **Event ID 10 — Process Access**

## Why It Matters
This may indicate:
- Credential theft tools  
- Process injection  
- Malware running under SYSTEM  

## Investigation Steps
1. Check if the process was **injected** (Event ID 10).  
2. Look for **CreateRemoteThread** (Event ID 8).  
3. Review **Process Tampering** (Event ID 25).  
4. Pivot to **Image Loaded** (Event ID 7).  
5. Investigate **service persistence** (Event ID 13).
