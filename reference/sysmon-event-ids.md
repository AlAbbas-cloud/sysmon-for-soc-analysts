# Sysmon Event ID Reference

This document provides a clear, SOC‑focused reference for all Sysmon Event IDs (1–28).  
Each entry includes the event name, what it detects, and why it matters for threat hunting and incident response.

Sysmon is most effective when analysts understand the behavioural meaning behind each event — not just the definition.  
Use this file as a quick‑reference guide during investigations, hunts, and detection engineering.

---

## Event ID Overview Table

| Event ID | Name | What It Detects (SOC Meaning) |
|---------:|------|--------------------------------|
| **1** | Process Create | New process execution. Critical for spotting malware, LOLBIN abuse, suspicious command lines. |
| **2** | File Creation Time Changed | Timestamp manipulation (timestomping). Used to hide malware. |
| **3** | Network Connection | Outbound connections. Detects C2, beaconing, lateral movement. |
| **4** | Sysmon Service State Changed | Sysmon start/stop. Attackers may try to disable logging. |
| **5** | Process Terminated | Process exit. Helps reconstruct timelines. |
| **6** | Driver Loaded | Kernel driver loads. Detects rootkits and malicious drivers. |
| **7** | Image Loaded | DLL loads. Key for detecting DLL injection/hijacking. |
| **8** | CreateRemoteThread | Remote thread creation. Strong signal for process injection. |
| **9** | RawAccessRead | Raw disk reads. Used by rootkits, forensic tools, malware. |
| **10** | Process Access | One process opening another. Detects LSASS access, credential theft, injection attempts. |
| **11** | File Create | File creation. Detects dropped payloads, ransomware staging. |
| **12** | Registry Object Added/Deleted | Registry key creation/deletion. Persistence and config changes. |
| **13** | Registry Value Set | Registry value modification. Detects Run‑key persistence (T1060). |
| **14** | Registry Object Renamed | Registry key renaming. Used to hide persistence. |
| **15** | FileCreateStreamHash | Alternate Data Streams (ADS). Detects hidden malware. |
| **16** | Sysmon Configuration Change | Sysmon config updated. Attackers may weaken logging. |
| **17** | Pipe Created | Named pipe creation. Malware IPC, C2 channels. |
| **18** | Pipe Connected | Process connecting to a named pipe. Malware communication. |
| **19** | WMI Event Filter | WMI filter creation. WMI persistence. |
| **20** | WMI Event Consumer | WMI consumer creation. WMI persistence. |
| **21** | WMI Filter‑to‑Consumer Binding | Binding of WMI persistence components. |
| **22** | DNS Query | DNS lookups. Detects beaconing, DGAs, suspicious domains. |
| **23** | File Delete (Archived) | File deletion with content archived. Anti‑forensics detection. |
| **24** | Clipboard Change | Clipboard access. Detects clipboard‑stealing malware. |
| **25** | Process Tampering | Image tampering. Detects process hollowing, PE injection. |
| **26** | File Delete | File deletion (non‑archived). Malware cleanup. |
| **27** | File Block Executable | Sysmon blocked execution. Used with blocking rules. |
| **28** | File Block Shredding | Sysmon blocked shredding. Detects anti‑forensics. |

---

# Detailed Event Explanations

Below is a deeper SOC‑focused breakdown of each event.

---

## **Event ID 1 - Process Create**
Captures every new process execution.  
**Why it matters:**  
- Detects malware execution  
- Shows parent/child relationships  
- Reveals LOLBIN abuse  
- Exposes encoded PowerShell commands  

---

## **Event ID 2 - File Creation Time Changed**
Detects timestomping.  
**Why it matters:**  
Attackers modify timestamps to hide malware or blend into system files.

---

## **Event ID 3 - Network Connection**
Logs outbound TCP/UDP connections.  
**Why it matters:**  
- Detects C2 traffic  
- Identifies reverse shells  
- Shows lateral movement  

---

## **Event ID 4 - Sysmon Service State Changed**
Triggered when Sysmon is stopped or restarted.  
**Why it matters:**  
Attackers often try to disable logging.

---

## **Event ID 5 - Process Terminated**
Logs when a process exits.  
**Why it matters:**  
Useful for reconstructing attack timelines.

---

## **Event ID 6 - Driver Loaded**
Logs kernel driver loads.  
**Why it matters:**  
Detects rootkits and malicious drivers.

---

## **Event ID 7 - Image Loaded**
Logs DLL loads.  
**Why it matters:**  
- Detects DLL injection  
- Identifies malicious modules  
- Reveals credential‑related DLLs  

---

## **Event ID 8 - CreateRemoteThread**
Logs remote thread creation.  
**Why it matters:**  
One of the strongest indicators of process injection.

---

## **Event ID 9 - RawAccessRead**
Logs raw disk reads.  
**Why it matters:**  
Used by:
- Rootkits  
- Forensic tools  
- Malware attempting stealth  

---

## **Event ID 10 - Process Access**
Logs when one process accesses another.  
**Why it matters:**  
- Detects LSASS access (Mimikatz)  
- Identifies token theft  
- Reveals injection attempts  

---

## **Event ID 11 - File Create**
Logs file creation.  
**Why it matters:**  
- Detects dropped payloads  
- Ransomware staging  
- Malware unpacking  

---

## **Event ID 12 - Registry Object Added/Deleted**
Logs registry key creation/deletion.  
**Why it matters:**  
Persistence and configuration changes.

---

## **Event ID 13 - Registry Value Set**
Logs registry value modifications.  
**Why it matters:**  
- Run key persistence  
- Script execution entries  
- Service modifications  

---

## **Event ID 14 - Registry Object Renamed**
Logs renaming of registry keys.  
**Why it matters:**  
Used to hide persistence.

---

## **Event ID 15 - FileCreateStreamHash**
Logs creation of Alternate Data Streams.  
**Why it matters:**  
Attackers hide payloads in ADS.

---

## **Event ID 16 - Sysmon Configuration Change**
Logs config updates.  
**Why it matters:**  
Attackers may weaken logging.

---

## **Event ID 17 & 18 - Pipe Created / Pipe Connected**
Logs named pipe activity.  
**Why it matters:**  
Malware uses pipes for:
- C2  
- Lateral movement  
- Internal communication  

---

## **Event ID 19–21 - WMI Persistence**
Logs WMI filters, consumers, and bindings.  
**Why it matters:**  
Detects stealthy, long‑term persistence.

---

## **Event ID 22 - DNS Query**
Logs DNS lookups.  
**Why it matters:**  
- Detects beaconing  
- Identifies DGAs  
- Reveals suspicious domains  

---

## **Event ID 23 - File Delete (Archived)**
Logs file deletion with content archived.  
**Why it matters:**  
Anti‑forensics detection.

---

## **Event ID 24 - Clipboard Change**
Logs clipboard access.  
**Why it matters:**  
Detects clipboard‑stealing malware.

---

## **Event ID 25 - Process Tampering**
Logs image tampering.  
**Why it matters:**  
Detects:
- Process hollowing  
- PE injection  

---

## **Event ID 26 - File Delete**
Logs file deletion (non‑archived).  
**Why it matters:**  
Malware cleanup.

---

## **Event ID 27 & 28 - File Block Executable / Shredding**
Logs Sysmon blocking actions.  
**Why it matters:**  
Used in hardened environments to prevent execution or shredding.

---
