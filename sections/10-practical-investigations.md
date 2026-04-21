# 10 - Practical Investigations

This final section of this ![Tryhackme - sysmon](https://tryhackme.com/room/sysmon) room brings together all Sysmon concepts learned throughout the room and applies them to real attack scenarios.  
Each investigation simulates a real SOC case, requiring you to analyze Sysmon logs, identify attacker behaviour, and reconstruct the intrusion chain.

The investigations cover:
- Malicious USB activity  
- HTML‑based payload execution  
- Persistence mechanisms  
- C2 communications  
- Malware staging and execution  
- Credential theft and evasion  

These scenarios mirror real-world incidents handled by SOC analysts.

---

## Investigation 1 - Malicious USB Drop

A malicious USB device was connected to a host, triggering suspicious activity.

### Key Findings
- A USB storage device triggered **RawAccessRead** events.  
- The device path and registry key revealed the exact USB identifier.  
- The first malicious process executed was **rundll32.exe**, a common LOLBIN used to run malicious DLLs.  
- Sysmon Event IDs 1, 11, and 12 were critical in reconstructing the chain.

### Skills Demonstrated
- Device identification  
- Process chain reconstruction  
- Detecting LOLBIN abuse  
- Registry analysis  

---

## Investigation 2 — Malicious HTML File

A file disguised as an HTML document executed malicious code.

### Key Findings
- The payload was actually an **HTA file**, not HTML.  
- The file was executed by **mshta.exe**, a signed Microsoft binary often abused for malware delivery.  
- The payload connected back to an attacker IP on port **4443**.  
- Sysmon revealed both the masqueraded file and the true payload path.

### Skills Demonstrated
- File masquerading detection  
- LOLBIN execution analysis  
- Network connection tracing  
- Payload staging identification  

---

## Investigation 3.1 — Registry‑Based Persistence

Attackers established persistence via the Windows registry.

### Key Findings
- The adversary stored a Base64 payload in a registry key under:  
  `HKLM\SOFTWARE\Microsoft\Network\debug`  
- PowerShell was launched with a command that decoded and executed the payload.  
- The endpoint hostname and attacker IP were identified from Sysmon logs.  
- The C2 hostname was revealed through DNS and network events.

### Skills Demonstrated
- Registry persistence detection  
- PowerShell payload decoding  
- Host and adversary identification  
- C2 infrastructure analysis  

---

## Investigation 3.2 — Scheduled Task Persistence

Attackers created a scheduled task to maintain access.

### Key Findings
- A scheduled task named **Updater** was created using `schtasks.exe`.  
- The task executed a hidden PowerShell command that decoded a Base64 payload stored in a file.  
- The payload file was located at:  
  `c:\users\q\AppData\blah.txt`  
- Sysmon revealed suspicious access to LSASS and other sensitive processes.

### Skills Demonstrated
- Scheduled task analysis  
- File‑based payload detection  
- Process access monitoring  
- Persistence chain reconstruction  

---

## Investigation 4 - Botnet / C2 Communications

The adversary established command‑and‑control communications on the endpoint.

### Key Findings
- Sysmon logs revealed outbound connections to a suspicious IP.  
- The attacker operated on a specific port associated with C2 frameworks.  
- The C2 type (e.g., Empire, Metasploit, custom botnet) was identified through process behaviour and network patterns.  
- Event ID 3 (Network Connection) and Event ID 1 (Process Create) were essential.

### Skills Demonstrated
- C2 detection  
- Network hunting  
- Beaconing pattern identification  
- Malware communication analysis  

---

## What This Section Demonstrates

By completing these investigations, you have shown the ability to:

- Analyze Sysmon logs in real attack scenarios  
- Identify malware behaviour and persistence  
- Detect LOLBIN abuse and evasion techniques  
- Reconstruct full attack chains  
- Attribute attacker infrastructure  
- Apply SOC‑grade investigation workflows  

This section represents the practical, hands‑on capability that SOC teams look for in analysts.



**Next step:** Build the README.md to tie the entire repo together.

