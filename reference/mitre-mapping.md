# MITRE ATT&CK Mapping for Sysmon

This reference maps Sysmon Event IDs to MITRE ATT&CK techniques.  
It helps SOC analysts quickly understand **which attacker behaviours** each Sysmon event can reveal.

Use this file during:
- Threat hunting  
- Detection engineering  
- Incident response  
- Investigation triage  
- Writing Sigma rules  
- Building detection pipelines  

---

# Quick Mapping Table

| Sysmon Event ID | Event Name | MITRE Technique(s) |
|----------------:|------------|---------------------|
| **1** | Process Create | T1059 (Command Execution), T1204 (User Execution), T1106 (Native API), T1218 (LOLBIN Abuse) |
| **2** | File Creation Time Changed | T1070.006 (Timestomp) |
| **3** | Network Connection | T1071 (C2), T1041 (Exfiltration), T1021 (Lateral Movement) |
| **4** | Sysmon Service State Changed | T1562.001 (Disable Security Tools) |
| **5** | Process Terminated | T1059 (Execution), timeline reconstruction |
| **6** | Driver Loaded | T1547.006 (Boot/Logon Autostart), T1068 (Privilege Escalation), rootkits |
| **7** | Image Loaded | T1574.002 (DLL Search Order Hijacking), T1055 (Injection) |
| **8** | CreateRemoteThread | T1055.001 (Process Injection) |
| **9** | RawAccessRead | T1003 (Credential Access), T1014 (Rootkits) |
| **10** | Process Access | T1003.001 (LSASS Dumping), T1055 (Injection), T1134 (Token Manipulation) |
| **11** | File Create | T1105 (Ingress Tool Transfer), T1486 (Ransomware), T1204 (User Execution) |
| **12** | Registry Object Added/Deleted | T1112 (Modify Registry), T1547 (Persistence) |
| **13** | Registry Value Set | T1547.001 (Run Keys), T1112 (Registry Modification) |
| **14** | Registry Object Renamed | T1112 (Registry Modification), stealthy persistence |
| **15** | FileCreateStreamHash | T1564.004 (Hide Artifacts — ADS) |
| **16** | Sysmon Config Change | T1562.001 (Disable Security Tools) |
| **17** | Pipe Created | T1047 (WMI), T1570 (Lateral Movement), malware IPC |
| **18** | Pipe Connected | T1047 (WMI), C2 channels |
| **19** | WMI Event Filter | T1546.003 (WMI Persistence) |
| **20** | WMI Event Consumer | T1546.003 (WMI Persistence) |
| **21** | WMI Filter-to-Consumer Binding | T1546.003 (WMI Persistence) |
| **22** | DNS Query | T1071.004 (DNS C2), T1568 (Dynamic Resolution), DGA detection |
| **23** | File Delete (Archived) | T1070.004 (File Deletion — Anti-Forensics) |
| **24** | Clipboard Change | T1115 (Clipboard Data Theft) |
| **25** | Process Tampering | T1055 (Process Injection), T1036 (Masquerading) |
| **26** | File Delete | T1070.004 (Anti-Forensics) |
| **27** | File Block Executable | Defensive control (Sysmon blocking) |
| **28** | File Block Shredding | Defensive control (Sysmon blocking) |

---

#  Detailed MITRE Technique Mapping

Below is a deeper explanation of how each Sysmon event aligns with attacker behaviour.

---

## **Event ID 1 - Process Create**
**MITRE Techniques:**
- T1059 — Command Execution  
- T1204 — User Execution  
- T1106 — Native API  
- T1218 — Signed Binary Proxy Execution (LOLBINs)

**Why it matters:**  
Nearly every attack begins with process execution. This event is foundational for detection.

---

## **Event ID 2 - File Creation Time Changed**
**MITRE Technique:**  
- T1070.006 — Timestomp

Attackers modify timestamps to hide malware or blend into system files.

---

## **Event ID 3 - Network Connection**
**MITRE Techniques:**
- T1071 — Command & Control  
- T1041 — Exfiltration  
- T1021 — Lateral Movement  

Critical for detecting beaconing, reverse shells, and C2.

---

## **Event ID 4 - Sysmon Service State Changed**
**MITRE Technique:**  
- T1562.001 - Disable Security Tools

Attackers often attempt to stop Sysmon.

---

## **Event ID 6 - Driver Loaded**
**MITRE Techniques:**
- T1547.006 — Kernel Autostart  
- T1068 — Privilege Escalation  
- Rootkit behaviour

---

## **Event ID 7 - Image Loaded**
**MITRE Techniques:**
- T1574.002 — DLL Search Order Hijacking  
- T1055 — Process Injection  

---

## **Event ID 8 - CreateRemoteThread**
**MITRE Technique:**  
- T1055.001 — Process Injection

One of the strongest indicators of malicious activity.

---

## **Event ID 9 - RawAccessRead**
**MITRE Techniques:**
- T1003 — Credential Access  
- T1014 — Rootkits  

---

## **Event ID 10 - Process Access**
**MITRE Techniques:**
- T1003.001 — LSASS Dumping  
- T1055 — Injection  
- T1134 — Token Manipulation  

This is your primary Mimikatz detection event.

---

## **Event ID 11 - File Create**
**MITRE Techniques:**
- T1105 — Ingress Tool Transfer  
- T1486 — Ransomware  
- T1204 — User Execution  

---

## **Event ID 12-14 - Registry Events**
**MITRE Techniques:**
- T1112 — Modify Registry  
- T1547 — Persistence (Run Keys, Services, etc.)

---

## **Event ID 15 - FileCreateStreamHash**
**MITRE Technique:**  
- T1564.004 — Hide Artifacts (ADS)

---

## **Event ID 16 - Sysmon Config Change**
**MITRE Technique:**  
- T1562.001 — Disable Security Tools

---

## **Event ID 17-18 - Named Pipes**
**MITRE Techniques:**
- T1047 — WMI  
- T1570 — Lateral Movement  
- Malware IPC channels

---

## **Event ID 19-21 - WMI Persistence**
**MITRE Technique:**  
- T1546.003 — WMI Event Subscription

---

## **Event ID 22 - DNS Query**
**MITRE Techniques:**
- T1071.004 — DNS C2  
- T1568 — Dynamic Resolution  

---

## **Event ID 23-26 - File Deletion / Tampering**
**MITRE Techniques:**
- T1070.004 — File Deletion  
- T1055 — Process Injection  
- T1036 — Masquerading  

---

# ✔ This file is now complete and ready for your repo.

