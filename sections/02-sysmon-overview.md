# 02 - Sysmon Overview

Sysmon (System Monitor) is part of Microsoft’s Sysinternals suite and provides detailed, high‑fidelity telemetry about what is happening inside a Windows system. It extends the visibility of traditional Windows Event Logs by capturing rich process, network, file, registry, and driver activity that attackers rely on during intrusions.

For SOC analysts, Sysmon acts as a behavioural sensor — it reveals *how* an attack unfolds, not just *that* something happened.

---

## What Sysmon Provides

Sysmon generates structured event logs that capture:

- **Process creation** (command lines, parent/child relationships)
- **Network connections** (source/destination IPs and ports)
- **File creation and modification**
- **Registry changes**
- **Driver and DLL loading**
- **Process access attempts** (e.g., LSASS access)
- **Named pipe creation** (malware IPC)
- **DNS queries**
- **Persistence mechanisms**
- **Evasion attempts**

This level of detail allows defenders to detect:

- Malware execution  
- Credential theft  
- Lateral movement  
- Persistence techniques  
- C2 communication  
- Process injection  
- Anti‑forensic behaviour  

---

## Why Sysmon Is Essential for Detection

Traditional Windows logs often lack context. Sysmon fills those gaps by providing:

### **1. Full command‑line visibility**  
Critical for spotting malicious PowerShell, LOLBIN abuse, and encoded payloads.

### **2. Parent/child process relationships**  
Helps analysts identify suspicious process chains (e.g., Word → PowerShell → mshta).

### **3. Network telemetry tied to processes**  
Shows *which* process made a connection — something Windows logs don’t provide by default.

### **4. File and registry monitoring**  
Essential for detecting persistence and malware staging.

### **5. Behaviour‑based detection**  
Sysmon logs attacker *behaviour*, not just signatures.

---

## Sysmon in the SOC Workflow

Sysmon is used in:

- **Threat hunting**  
- **Incident response**  
- **Malware analysis**  
- **Detection engineering**  
- **Blue‑team investigations**

It provides the raw data needed to:

- Reconstruct attack timelines  
- Identify initial access  
- Trace payload execution  
- Detect persistence  
- Understand attacker intent  

---

## What This Section Sets Up

This overview prepares you for the rest of the repository by explaining:

- What Sysmon captures  
- Why its telemetry is valuable  
- How it fits into real SOC operations  

The next sections build on this foundation, covering installation, configuration, noise reduction, and practical hunting techniques.

---

**Next:** [03 — Installing and Preparing Sysmon](./03-installing-sysmon.md)

