# Sysmon for SOC Analysts  
A complete Sysmon detection and hunting repository demonstrating practical SOC skills.  
Includes Sysmon configuration, event analysis, malware hunting, persistence detection, evasion techniques, diagrams, and full automation scripts.

---

# Overview

This repository is designed as a **hands‑on SOC analyst portfolio**, showing how Sysmon telemetry can be used to detect:

- Malware execution  
- Process injection  
- Persistence mechanisms  
- Network‑based threats  
- PowerShell abuse  
- Registry tampering  
- Evasion techniques  

It includes:

- **Step‑by‑step hunting guides**  
- **Practical investigations**  
- **TryHackMe‑based learning notes**  
- **Automation scripts for real SOC workflows**  
- **Visual diagrams**  
- **MITRE ATT&CK mappings**  

Everything here is built to reflect **real SOC analyst workflows**.

---

# Folder Structure

```text
sysmon-for-soc-analysts/
│
├── sections/
│   ├── 01-introduction.md
│   ├── 02-sysmon-overview.md
│   ├── 03-installing-sysmon.md
│   ├── 04-cutting-noise.md
│   ├── 05-hunting-metasploit.md
│   ├── 06-detecting-mimikatz.md
│   ├── 07-hunting-malware.md
│   ├── 08-hunting-persistence.md
│   ├── 09-detecting-evasion.md
│   └── 10-practical-investigations.md
│
├── hunts/
│   ├── process-hunts.md
│   ├── network-hunts.md
│   ├── dns-hunts.md
│   ├── registry-hunts.md
│   ├── injection-hunts.md
│   ├── persistence-hunts.md
│   └── powershell-hunts.md
│
├── powershell/
│   ├── hunt-all.ps1
│   ├── hunt-process.ps1
│   ├── hunt-network.ps1
│   ├── hunt-dns.ps1
│   ├── hunt-registry.ps1
│   ├── hunt-injection.ps1
│   ├── hunt-persistence.ps1
│   └── hunt-powershell.ps1
│
├── diagrams/
│   ├── sysmon-overview.md
│   ├── hunting-flow.md
│   ├── injection-flow.md
│   ├── persistence-flow.md
│   └── event-id-map.md
│
├── reference/
│   ├── sysmon-event-ids.md
│   ├── mitre-mapping.md
│   └── lolbins.md
│
└── README.md
```

## What This Repository Demonstrates

### Real SOC Analyst Skills
Every hunt, script, and diagram is built to reflect real-world detection engineering and threat hunting.

### Sysmon Mastery
Deep understanding of:
- Event IDs  
- Telemetry relationships  
- Detection logic  
- Noise reduction  
- Pivoting between events  

### Automation
All hunts are backed by PowerShell automation scripts that replicate SOC workflows.

### Visual Storytelling
Diagrams help explain:
- Process injection  
- Persistence chains  
- Sysmon event flow  
- Hunting logic  

### MITRE ATT&CK Alignment
Each hunt maps to relevant ATT&CK techniques.

---

## Acknowledgment & Credit

This project was heavily inspired by hands‑on learning from **TryHackMe**, especially the excellent **Sysmon** room:

👉 [Tryhackme Sysmon Room](https://tryhackme.com/room/sysmon)

TryHackMe provided the foundation for:
- Understanding Sysmon event IDs  
- Building detection logic  
- Practicing real-world hunting scenarios  
- Strengthening SOC investigation skills  

Massive credit to their platform for enabling practical, accessible cybersecurity learning.

---

## Automation Scripts

The `/powershell` folder contains SOC‑grade hunting tools:

- `hunt-process.ps1` — LOLBINs, suspicious parents, encoded commands  
- `hunt-network.ps1` — beaconing, DDNS, tunneling  
- `hunt-dns.ps1` — DGA, tunneling, system DNS  
- `hunt-registry.ps1` — autoruns, services, evasion keys  
- `hunt-injection.ps1` — remote threads, LSASS access, DLL loads  
- `hunt-persistence.ps1` — WMI, startup, services, Sysmon tampering  
- `hunt-powershell.ps1` — AMSI bypass, download cradles, lateral movement  
- `hunt-all.ps1` — full suite execution  

These scripts turn Sysmon logs into actionable intelligence.

---

## MITRE ATT&CK Coverage

This repo covers techniques across:
- Execution  
- Persistence  
- Privilege Escalation  
- Defense Evasion  
- Credential Access  
- Discovery  
- Lateral Movement  
- Command & Control  

See `/reference/mitre-mapping.md` for full mapping.

---

## Future Additions

- Sigma rule conversions  
- ELK dashboards  
- Sysmon config tuning examples  
- More TryHackMe investigation write-ups  
- Blue team lab scenarios  

---

## Contributions

Pull requests are welcome — especially improvements to:
- Detection logic  
- PowerShell scripts  
- Diagrams  
- Hunting workflows  

---

## Contact

If you’d like to collaborate, discuss SOC workflows, or share ideas, feel free to reach out via GitHub.

---

## Stay Sharp, Stay Curious

This repo is built to show **practical, real-world SOC capability** — not theory.  
Every file exists because it solves a real detection or hunting problem.

**Happy hunting!**

