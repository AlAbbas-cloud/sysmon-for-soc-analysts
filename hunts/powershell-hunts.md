# PowerShell Hunts (Sysmon Event IDs)

This section provides practical, SOC‑focused hunting workflows for detecting malicious or suspicious PowerShell activity using Sysmon telemetry.  
PowerShell is one of the most abused components in modern attacks, used for recon, payload delivery, C2, and in‑memory execution.

Each hunt includes:  
- **What to look for**  
- **Relevant Sysmon Event IDs**  
- **Why it matters**  
- **How to investigate further**  
- **Common attacker behaviours**

---

# 1. Hunt: Encoded or Obfuscated PowerShell

## What to Look For
PowerShell commands that use:
- `-enc`, `-encodedcommand`
- `-nop`, `-noprofile`
- `-w hidden`, `-windowstyle hidden`
- Long base64 strings
- Heavy use of `FromBase64String`, `IEX`, `Invoke-Expression`

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 3 — Network Connection**
- **Event ID 7 — Image Loaded**

## Why It Matters
Encoded PowerShell is a strong indicator of:
- Malware loaders  
- C2 stagers  
- In‑memory execution  
- Script‑based attacks  

## Investigation Steps
1. Extract and decode base64 command lines.  
2. Identify the **parent process** (Office, browser, script host).  
3. Pivot to **network connections** (Event ID 3).  
4. Review **DLL loads** (Event ID 7) for AMSI bypasses.  
5. Check for **file creation** (Event ID 11) for dropped payloads.

---

# 2. Hunt: PowerShell Download Cradle

## What to Look For
PowerShell used to download and execute content:

Common patterns:
- `Invoke-WebRequest`, `Invoke-RestMethod`
- `System.Net.WebClient`
- `DownloadString`, `DownloadFile`
- URLs in command line (HTTP/HTTPS)

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 3 — Network Connection**
- **Event ID 22 — DNS Query**

## Why It Matters
Download cradles are used to:
- Fetch payloads  
- Stage malware  
- Pull down scripts from paste sites or GitHub  

## Investigation Steps
1. Extract URLs from the command line.  
2. Check **destination IPs/domains** for reputation.  
3. Pivot to **file creation** (Event ID 11).  
4. Review **registry persistence** (Event ID 13).  
5. Look for **follow‑on PowerShell** or LOLBIN activity.

---

# 3. Hunt: PowerShell as a Child of Office or Browsers

## What to Look For
PowerShell spawned by:

- `winword.exe`, `excel.exe`, `powerpnt.exe`  
- `outlook.exe`  
- `chrome.exe`, `msedge.exe`, `iexplore.exe`  

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 3 — Network Connection**

## Why It Matters
This is a classic sign of:
- Macro‑based malware  
- Phishing payloads  
- Malicious documents  

## Investigation Steps
1. Identify the **document** or **URL** that triggered execution.  
2. Review the **PowerShell command line**.  
3. Pivot to **network connections** (Event ID 3).  
4. Check for **file creation** (Event ID 11).  
5. Investigate **persistence** (Event ID 13 or WMI events).

---

# 4. Hunt: PowerShell with AMSI / Logging Bypass

## What to Look For
PowerShell commands that attempt to disable or bypass:

- AMSI  
- Script block logging  
- Module logging  

Common patterns:
- `AmsiUtils`, `amsiInitFailed`
- `Add-Type` with AMSI patching code
- Registry changes to logging keys

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 7 — Image Loaded**
- **Event ID 13 — Registry Value Set**

## Why It Matters
Attackers disable logging to:
- Hide malicious scripts  
- Evade EDR and AV  
- Run payloads in memory  

## Investigation Steps
1. Look for **AMSI‑related DLLs** in Event ID 7.  
2. Check **registry keys** related to PowerShell logging (Event ID 13).  
3. Pivot to **Process Access** (Event ID 10).  
4. Review **network connections** (Event ID 3).  
5. Investigate **follow‑on processes** spawned by PowerShell.

---

# 5. Hunt: PowerShell Used for Lateral Movement

## What to Look For
PowerShell used with:

- `Invoke-Command`  
- `Enter-PSSession`  
- `New-PSSession`  
- `WinRM` endpoints  
- Remote computer names or IPs in arguments  

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 3 — Network Connection**

## Why It Matters
PowerShell Remoting is commonly used for:
- Lateral movement  
- Remote code execution  
- Domain‑wide attacks  

## Investigation Steps
1. Identify **source → destination** hosts.  
2. Check for **credential theft** indicators (Event ID 10 to LSASS).  
3. Pivot to **service creation** or **registry persistence** (Event ID 13).  
4. Review **file creation** (Event ID 11) for tools (PsExec, custom scripts).  
5. Investigate **WMI persistence** (Event IDs 19–21).

---

# 6. Hunt: PowerShell Living Off the Land (LOLBIN Abuse)

## What to Look For
PowerShell used in combination with:

- `rundll32.exe`  
- `regsvr32.exe`  
- `mshta.exe`  
- `wmic.exe`  
- `certutil.exe`  

## Relevant Sysmon Events
- **Event ID 1 — Process Create**
- **Event ID 3 — Network Connection**
- **Event ID 7 — Image Loaded**

## Why It Matters
Attackers chain LOLBINs with PowerShell to:
- Evade application control  
- Blend into normal activity  
- Execute payloads stealthily  

## Investigation Steps
1. Map **parent/child relationships** between LOLBINs and PowerShell.  
2. Review **command lines** for encoded or remote content.  
3. Pivot to **network connections** (Event ID 3).  
4. Check for **file creation** (Event ID 11).  
5. Investigate **registry persistence** (Event ID 13).
