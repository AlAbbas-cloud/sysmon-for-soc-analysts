# Process Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting suspicious or malicious process activity using Sysmon telemetry.  
Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**  

---

# 🔥 1. Hunt: Suspicious Process Creation (Event ID 1)

## What to Look For
Processes that are unusual, unexpected, or known to be abused by attackers.

## Key Indicators
- LOLBIN execution (e.g., `rundll32.exe`, `mshta.exe`, `regsvr32.exe`)
- PowerShell with encoded commands
- Command prompt spawning child processes
- Unexpected parent/child relationships

## Relevant Sysmon Events
- **Event ID 1 — Process Create**

## Why It Matters
Nearly every attack begins with process execution.  
This is the highest‑value event for initial triage.

## Investigation Steps
1. Check the **parent process** — is it expected?  
2. Review the **command line** — encoded, obfuscated, or suspicious?  
3. Look for **network activity** (Event ID 3).  
4. Check for **file drops** (Event ID 11).  
5. Pivot to **registry changes** (Event ID 13) for persistence.

---

# 🔥 2. Hunt: PowerShell Abuse

## What to Look For
PowerShell used for:
- Downloading payloads  
- Running encoded commands  
- In‑memory execution  
- Reconnaissance  

## Relevant Sysmon Events
- **Event ID 1 — Process Create**  
- **Event ID 3 — Network Connection**  
- **Event ID 7 — Image Loaded**  
- **Event ID 10 — Process Access**

## Why It Matters
PowerShell is one of the most abused LOLBINs in Windows environments.

## Investigation Steps
1. Look for `-enc`, `-nop`, `-w hidden`, `-c`, or base64 strings.  
2. Check if PowerShell spawned unusual children (e.g., `cmd.exe`, `rundll32.exe`).  
3. Look for outbound connections (Event ID 3).  
4. Check for DLL loads (Event ID 7) indicating AMSI bypasses.  
5. Pivot to **Process Access** (Event ID 10) for injection attempts.

---

# 🔥 3. Hunt: Process Injection Attempts

## What to Look For
Processes attempting to access or inject into other processes.

## Relevant Sysmon Events
- **Event ID 10 — Process Access**  
- **Event ID 8 — CreateRemoteThread**  
- **Event ID 25 — Process Tampering**

## Why It Matters
Process injection is a strong indicator of malware, credential theft, or evasion.

## Investigation Steps
1. Identify the **source process** — is it legitimate?  
2. Identify the **target process** — LSASS, winlogon, explorer?  
3. Look for **CreateRemoteThread** events (Event ID 8).  
4. Check for **Process Tampering** (Event ID 25).  
5. Pivot to **Image Loaded** (Event ID 7) for DLL injection.

---

# 🔥 4. Hunt: Suspicious Parent/Child Relationships

## What to Look For
Processes spawning children they normally shouldn’t.

## Examples
- `winword.exe` → `cmd.exe`  
- `excel.exe` → `powershell.exe`  
- `svchost.exe` → `rundll32.exe`  
- `explorer.exe` → `wscript.exe`

## Relevant Sysmon Events
- **Event ID 1 — Process Create**

## Why It Matters
Attackers often abuse legitimate applications to launch malicious payloads.

## Investigation Steps
1. Validate whether the parent process normally spawns the child.  
2. Review the command line for suspicious arguments.  
3. Check for **network connections** (Event ID 3).  
4. Look for **file creation** (Event ID 11).  
5. Pivot to **registry changes** (Event ID 13) for persistence.

---

# 🔥 5. Hunt: LOLBIN Abuse

## What to Look For
Legitimate Windows binaries used for malicious purposes.

## Common LOLBINs
- `rundll32.exe`  
- `regsvr32.exe`  
- `mshta.exe`  
- `wmic.exe`  
- `bitsadmin.exe`  
- `certutil.exe`  

## Relevant Sysmon Events
- **Event ID 1 — Process Create**  
- **Event ID 3 — Network Connection**  
- **Event ID 7 — Image Loaded**

## Why It Matters
LOLBINs allow attackers to bypass security controls and execute payloads stealthily.

## Investigation Steps
1. Check the command line for remote URLs or suspicious DLLs.  
2. Look for network activity (Event ID 3).  
3. Check for DLL loads (Event ID 7).  
4. Pivot to **file creation** (Event ID 11).  
5. Investigate persistence (Event ID 13 or WMI events).

---

# 🔥 6. Hunt: Suspicious Terminated Processes

## What to Look For
Processes that terminate unexpectedly or rapidly.

## Relevant Sysmon Events
- **Event ID 5 — Process Terminated**

## Why It Matters
Malware often kills processes to disable security tools or hide activity.

## Investigation Steps
1. Identify the parent process.  
2. Check if the process normally terminates quickly.  
3. Look for **Process Access** (Event ID 10) before termination.  
4. Check for **Sysmon service tampering** (Event ID 4).  
5. Pivot to **file deletion** (Event ID 23/26) for cleanup activity.

---

# ✔ This file is now complete and ready for your repo.
