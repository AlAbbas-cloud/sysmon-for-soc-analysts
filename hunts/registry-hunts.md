# Registry Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting suspicious or malicious registry activity using Sysmon telemetry.  
Registry changes are one of the strongest indicators of persistence, configuration tampering, malware staging, and privilege escalation.

Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: Autorun Persistence (Run / RunOnce Keys)

## What to Look For
Registry keys that automatically execute programs at startup:

**Common autorun paths**
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
- Credential theft tools  
- Payload re‑execution after reboot  

## Investigation Steps
1. Identify the **value name** and **data** (path to executable).  
2. Check if the executable is in a suspicious location (e.g., `%AppData%`, `%Temp%`).  
3. Pivot to **Process Create** (Event ID 1) for the parent process.  
4. Look for **file creation** (Event ID 11) of the payload.  
5. Check for **WMI persistence** (Event IDs 19–21) as a backup mechanism.

---

# 2. Hunt: Service Creation / Modification

## What to Look For
Registry changes under:

- `HKLM\SYSTEM\CurrentControlSet\Services\*`

## Relevant Sysmon Events
- **Event ID 13 — Registry Value Set**
- **Event ID 12 — Registry Key Added**

## Why It Matters
Attackers create or modify services to:
- Maintain persistence  
- Run payloads as SYSTEM  
- Install backdoors  
- Disable security tools  

## Investigation Steps
1. Identify the **service name** and **ImagePath**.  
2. Check if the binary is legitimate.  
3. Pivot to **Process Create** (Event ID 1) for the parent.  
4. Look for **Process Access** (Event ID 10) targeting LSASS or winlogon.  
5. Review **Sysmon service state changes** (Event ID 4) for tampering.

---

# 3. Hunt: Registry-Based Malware Configuration

## What to Look For
Malware often stores:
- C2 URLs  
- Encryption keys  
- Payload paths  
- Execution flags  

Common locations:
- `HKCU\Software\<random>`  
- `HKCU\Software\Microsoft\<random>`  
- `HKLM\Software\<random>`  

## Relevant Sysmon Events
- **Event ID 13 — Registry Value Set**
- **Event ID 14 — Registry Key Renamed**

## Why It Matters
Registry-stored configuration is a hallmark of:
- RATs  
- Keyloggers  
- Stealers  
- Fileless malware  

## Investigation Steps
1. Look for **high‑entropy value names**.  
2. Check for **base64‑encoded strings**.  
3. Pivot to **DNS queries** (Event ID 22) for C2.  
4. Review **network connections** (Event ID 3).  
5. Check for **file creation** (Event ID 11) of dropped modules.

---

# 4. Hunt: Registry Tampering for Evasion

## What to Look For
Changes to security‑related registry keys:

Examples:
- Disabling Windows Defender  
- Disabling AMSI  
- Disabling UAC  
- Modifying audit policies  

## Relevant Sysmon Events
- **Event ID 13 — Registry Value Set**
- **Event ID 14 — Registry Key Renamed**

## Why It Matters
Attackers modify registry keys to:
- Disable detection  
- Reduce logging  
- Evade EDR  
- Lower system defenses  

## Investigation Steps
1. Identify the **exact key** modified.  
2. Check for **Process Access** (Event ID 10) from suspicious processes.  
3. Look for **Process Tampering** (Event ID 25).  
4. Pivot to **Image Loaded** (Event ID 7) for AMSI bypass DLLs.  
5. Review **Sysmon configuration changes** (Event ID 16).

---

# 5. Hunt: Registry Key Renaming (Stealth Persistence)

## What to Look For
Attackers rename registry keys to:
- Hide persistence  
- Break detection rules  
- Obfuscate malware configuration  

## Relevant Sysmon Events
- **Event ID 14 — Registry Key Renamed**

## Why It Matters
Renaming keys is a stealth technique used by:
- Advanced malware  
- Fileless loaders  
- WMI‑based persistence  
- Rootkits  

## Investigation Steps
1. Compare **old name vs new name**.  
2. Check for **Process Create** (Event ID 1) from suspicious parents.  
3. Look for **WMI persistence** (Event IDs 19–21).  
4. Review **file creation** (Event ID 11).  
5. Investigate **network activity** (Event ID 3) for C2.

---

# 6. Hunt: Registry Timestomping

## What to Look For
Attackers modify registry timestamps to hide activity.

## Relevant Sysmon Events
- **Event ID 12 — Registry Key Added/Deleted**
- **Event ID 13 — Registry Value Set**

## Why It Matters
Timestomping is used to:
- Blend into legitimate system activity  
- Evade timeline analysis  
- Hide persistence mechanisms  

## Investigation Steps
1. Compare timestamps with known system baselines.  
2. Pivot to **file timestomping** (Event ID 2).  
3. Look for **Process Access** (Event ID 10).  
4. Review **Process Tampering** (Event ID 25).  
5. Investigate **startup folder** (Event ID 11).
