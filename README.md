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
