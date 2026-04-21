# Injection Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting process injection, memory tampering, and stealthy execution using Sysmon telemetry.  
Process injection is one of the strongest indicators of malware, credential theft, evasion, and privilege escalation.

Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: Process Access (Event ID 10)

## What to Look For
Processes attempting to access the memory of other processes.

Common suspicious targets:
- `lsass.exe`  
- `winlogon.exe`  
- `explorer.exe`  
- `svchost.exe`  

Common suspicious sources:
- `powershell.exe`  
- `rundll32.exe`  
- `wmic.exe`  
- `python.exe`  
- Unknown binaries in `%AppData%` or `%Temp%`

## Relevant Sysmon Events
- **Event ID 10 — Process Access**

## Why It Matters
Process access is often the **first step** in:
- Credential theft  
- Process injection  
- Token manipulation  
- Memory scraping  

## Investigation Steps
1. Identify the **source process** — is it legitimate?  
2. Identify the **target process** — is it sensitive?  
3. Look for **CreateRemoteThread** (Event ID 8).  
4. Check for **Process Tampering** (Event ID 25).  
5. Pivot to **Image Loaded** (Event ID 7) for DLL injection.

---

# 2. Hunt: Remote Thread Creation (Event ID 8)

## What to Look For
A process creating a thread inside another process.

This is a classic sign of:
- Process hollowing  
- DLL injection  
- Reflective loading  
- Cobalt Strike beacons  
- Malware loaders  

## Relevant Sysmon Events
- **Event ID 8 — CreateRemoteThread**

## Why It Matters
This is one of the **highest‑signal** indicators of malicious activity.

## Investigation Steps
1. Identify the **source → target** process pair.  
2. Check if the target is a high‑value process (LSASS, winlogon).  
3. Look for **Process Access** (Event ID 10) leading up to it.  
4. Review **Image Loaded** (Event ID 7) for suspicious DLLs.  
5. Pivot to **Process Tampering** (Event ID 25).

---

# 3. Hunt: DLL Injection (Event ID 7)

## What to Look For
Suspicious DLLs loaded into processes.

Examples:
- DLLs loaded from `%Temp%`, `%AppData%`, `%ProgramData%`  
- DLLs with random names  
- DLLs not signed or mismatched signatures  
- DLLs loaded by processes that normally don’t load them  

## Relevant Sysmon Events
- **Event ID 7 — Image Loaded**

## Why It Matters
DLL injection is used for:
- Evasion  
- Credential theft  
- Keylogging  
- RAT persistence  
- AMSI bypasses  

## Investigation Steps
1. Identify the **DLL path** — is it legitimate?  
2. Check the **signing status**.  
3. Pivot to **Process Access** (Event ID 10).  
4. Look for **CreateRemoteThread** (Event ID 8).  
5. Review **Process Create** (Event ID 1) for the parent process.

---

# 4. Hunt: Process Tampering (Event ID 25)

## What to Look For
Processes modifying the memory or execution state of other processes.

Examples:
- Hollowing  
- Unmapping memory  
- Patching code  
- Overwriting sections  
- Manipulating handles  

## Relevant Sysmon Events
- **Event ID 25 — Process Tampering**

## Why It Matters
This is a strong indicator of:
- Malware loaders  
- In‑memory execution  
- EDR evasion  
- Credential theft tools  

## Investigation Steps
1. Identify the **tampered process**.  
2. Check for **Process Access** (Event ID 10).  
3. Look for **CreateRemoteThread** (Event ID 8).  
4. Review **Image Loaded** (Event ID 7).  
5. Pivot to **network activity** (Event ID 3) for C2.

---

# 5. Hunt: LSASS Access (Credential Theft)

## What to Look For
Any process accessing or injecting into `lsass.exe`.

## Relevant Sysmon Events
- **Event ID 10 — Process Access**  
- **Event ID 8 — CreateRemoteThread**  
- **Event ID 25 — Process Tampering**

## Why It Matters
This is a hallmark of:
- Mimikatz  
- Cobalt Strike  
- Empire  
- Credential dumping malware  

## Investigation Steps
1. Identify the **source process**.  
2. Check for **unsigned binaries**.  
3. Review **Image Loaded** (Event ID 7).  
4. Look for **network connections** (Event ID 3).  
5. Investigate **persistence** (Event ID 13 or WMI events).

---

# 6. Hunt: Suspicious Memory Reads (RawAccessRead)

## What to Look For
Processes reading raw disk or memory sectors.

## Relevant Sysmon Events
- **Event ID 9 — RawAccessRead**

## Why It Matters
Used by:
- Rootkits  
- Forensic tool abuse  
- Credential theft  
- Boot sector tampering  

## Investigation Steps
1. Identify the **process** performing the read.  
2. Check for **Process Access** (Event ID 10).  
3. Look for **Process Tampering** (Event ID 25).  
4. Review **Image Loaded** (Event ID 7).  
5. Pivot to **file creation** (Event ID 11) for dropped tools.
