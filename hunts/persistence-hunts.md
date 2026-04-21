# Persistence Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting persistence mechanisms using Sysmon telemetry.  
Persistence is how attackers maintain long‑term access to a system — often surviving reboots, credential resets, and malware removal.

Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: Registry Run Key Persistence

## What to Look For
Registry keys that automatically execute programs at startup:

Common autorun paths:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `RunOnce`, `RunServices`, `RunServicesOnce`

## Relevant Sysmon Events
- **Event ID 13 — Registry Value Set**
- **Event ID 12 — Registry Key Added/Deleted**

## Why It Matters
Attackers frequently use autorun keys for:
- Malware persistence  
- RAT startup  
- Payload re‑execution after reboot  

## Investigation Steps
1. Identify the **value name** and **executable path**.  
2. Check if the binary lives in `%AppData%`, `%Temp%`, or `%ProgramData%`.  
3. Pivot to **Process Create** (Event ID 1).  
4. Look for **file creation** (Event ID 11).  
5. Check for **WMI persistence** (Event IDs 19–21).

---

# 2. Hunt: Startup Folder Persistence

## What to Look For
Files created in:
- `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

## Relevant Sysmon Events
- **Event ID 11 — File Create**
- **Event ID 2 — File Creation Time Changed (timestomping)**

## Why It Matters
Attackers drop:
- EXEs  
- VBS scripts  
- PowerShell scripts  
- LNK shortcuts  

into the Startup folder to ensure execution at login.

## Investigation Steps
1. Identify the **file path** and **extension**.  
2. Check for timestomping (Event ID 2).  
3. Pivot to **Process Create** (Event ID 1).  
4. Review **registry changes** (Event ID 13).  
5. Investigate **network activity** (Event ID 3).

---

# 3. Hunt: WMI Event Subscription Persistence

## What to Look For
WMI persistence consists of three components:
- **Event Filter** (Event ID 19)  
- **Event Consumer** (Event ID 20)  
- **Filter‑to‑Consumer Binding** (Event ID 21)

## Relevant Sysmon Events
- **Event ID 19 — WMI Event Filter**
- **Event ID 20 — WMI Event Consumer**
- **Event ID 21 — WMI Filter-to-Consumer Binding**

## Why It Matters
WMI persistence is:
- Fileless  
- Hard to detect  
- Used by APTs  
- Used by stealthy malware  

## Investigation Steps
1. Identify the **filter query** — what triggers execution?  
2. Review the **consumer** — what payload is executed?  
3. Check for **Process Create** (Event ID 1) from suspicious parents.  
4. Look for **registry persistence** (Event ID 13).  
5. Pivot to **file creation** (Event ID 11).

---

# 4. Hunt: Service-Based Persistence

## What to Look For
Registry changes under:

- `HKLM\SYSTEM\CurrentControlSet\Services\*`

## Relevant Sysmon Events
- **Event ID 13 — Registry Value Set**
- **Event ID 12 — Registry Key Added**

## Why It Matters
Attackers create or modify services to:
- Maintain SYSTEM‑level persistence  
- Run payloads silently  
- Install backdoors  

## Investigation Steps
1. Identify the **service name** and **ImagePath**.  
2. Check if the binary is legitimate.  
3. Pivot to **Process Create** (Event ID 1).  
4. Review **Sysmon service state changes** (Event ID 4).  
5. Investigate **Process Access** (Event ID 10).

---

# 5. Hunt: DLL Search Order Hijacking

## What to Look For
Attackers place malicious DLLs in locations where Windows loads them before legitimate ones.

Common targets:
- `rundll32.exe`
- `explorer.exe`
- `svchost.exe`

## Relevant Sysmon Events
- **Event ID 7 — Image Loaded**
- **Event ID 11 — File Create**

## Why It Matters
DLL hijacking is used for:
- Stealthy persistence  
- Evasion  
- Privilege escalation  

## Investigation Steps
1. Identify DLLs loaded from unusual directories.  
2. Check for unsigned or mismatched signatures.  
3. Pivot to **Process Create** (Event ID 1).  
4. Look for **registry changes** (Event ID 13).  
5. Review **Process Access** (Event ID 10).

---

# 6. Hunt: Sysmon Configuration Tampering

## What to Look For
Changes to Sysmon configuration or service state.

## Relevant Sysmon Events
- **Event ID 4 — Sysmon Service State Changed**
- **Event ID 16 — Sysmon Configuration Change**

## Why It Matters
Attackers may:
- Disable Sysmon  
- Modify rules  
- Reduce logging  
- Evade detection  

## Investigation Steps
1. Identify the **process** modifying Sysmon.  
2. Check for **Process Access** (Event ID 10).  
3. Look for **Process Tampering** (Event ID 25).  
4. Review **registry changes** (Event ID 13).  
5. Investigate **file creation** (Event ID 11).
