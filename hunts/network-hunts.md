# Network Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting suspicious or malicious network activity using Sysmon telemetry.  
Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: Suspicious Outbound Connections (Event ID 3)

## What to Look For
Outbound connections to:
- Rare or unknown IPs  
- High‑risk geolocations  
- Non‑standard ports  
- Cloud storage providers  
- Dynamic DNS domains  

## Relevant Sysmon Events
- **Event ID 3 — Network Connection**

## Why It Matters
Outbound connections often reveal:
- C2 beacons  
- Reverse shells  
- Data exfiltration  
- Malware staging  

## Investigation Steps
1. Identify the **process** making the connection.  
2. Check the **destination IP/port** — is it expected?  
3. Review the **parent process** (Event ID 1).  
4. Look for **file drops** (Event ID 11).  
5. Pivot to **DNS queries** (Event ID 22).  
6. Check for **persistence** (Event ID 13 or WMI events).

---

# 2. Hunt: Beaconing Behaviour (C2)

## What to Look For
- Repeated connections at fixed intervals  
- Small, consistent payload sizes  
- Connections to cloud providers or VPS hosts  
- Long‑lived TCP sessions  

## Relevant Sysmon Events
- **Event ID 3 — Network Connection**

## Why It Matters
Beaconing is a hallmark of:
- RATs  
- Cobalt Strike  
- Metasploit  
- Custom malware  

## Investigation Steps
1. Look for **repeated connections** from the same process.  
2. Check for **encoded PowerShell** or LOLBIN usage.  
3. Pivot to **Process Access** (Event ID 10) for injection.  
4. Review **DNS queries** (Event ID 22).  
5. Check for **file creation** (Event ID 11) indicating payload staging.

---

# 3. Hunt: Suspicious DNS Queries (Event ID 22)

## What to Look For
- Algorithmically generated domains (DGA)  
- Long subdomains  
- Random character strings  
- DNS TXT record abuse  
- DNS tunneling patterns  

## Relevant Sysmon Events
- **Event ID 22 — DNS Query**

## Why It Matters
DNS is a common channel for:
- C2  
- Data exfiltration  
- Malware staging  
- Evasion  

## Investigation Steps
1. Look for **high‑entropy domain names**.  
2. Check if the domain is newly registered.  
3. Pivot to **Network Connections** (Event ID 3).  
4. Review the **process** making the DNS request.  
5. Check for **registry persistence** (Event ID 13).  
6. Investigate **WMI persistence** (Event IDs 19–21).

---

# 4. Hunt: Non‑Standard Ports

## What to Look For
Connections on:
- 8080, 8443  
- 4444 (Metasploit)  
- 1337, 9001  
- High ephemeral ports  

## Relevant Sysmon Events
- **Event ID 3 — Network Connection**

## Why It Matters
Attackers often avoid ports 80/443 to evade detection.

## Investigation Steps
1. Identify the **process** using the port.  
2. Check for **parent/child anomalies**.  
3. Look for **file creation** (Event ID 11).  
4. Pivot to **Process Access** (Event ID 10).  
5. Review **DNS queries** (Event ID 22).  

---

# 5. Hunt: Internal Lateral Movement

## What to Look For
Connections to:
- SMB (445)  
- RDP (3389)  
- WinRM (5985/5986)  
- WMI (135)  

## Relevant Sysmon Events
- **Event ID 3 — Network Connection**

## Why It Matters
Lateral movement is a critical stage in most intrusions.

## Investigation Steps
1. Identify the **source process** — PowerShell? WMI? PsExec?  
2. Check for **credential access** (Event ID 10).  
3. Look for **service creation** (Event ID 13).  
4. Pivot to **WMI persistence** (Event IDs 19–21).  
5. Review **file creation** (Event ID 11) for dropped tools.

---

# 6. Hunt: Data Exfiltration

## What to Look For
- Large outbound transfers  
- Uploads to cloud storage  
- DNS tunneling  
- HTTPS POST bursts  

## Relevant Sysmon Events
- **Event ID 3 — Network Connection**  
- **Event ID 22 — DNS Query**

## Why It Matters
Exfiltration is the final stage of most attacks.

## Investigation Steps
1. Identify the **process** sending large data volumes.  
2. Check for **compression tools** (7zip, rar).  
3. Look for **file staging** (Event ID 11).  
4. Review **registry persistence** (Event ID 13).  
5. Pivot to **Process Access** (Event ID 10) for injection.
