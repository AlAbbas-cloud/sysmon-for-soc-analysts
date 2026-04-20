# 01 - Introduction

Sysmon (System Monitor) is a Windows system service and driver that provides deep visibility into process activity, network connections, file changes, and other critical system events. Unlike standard Windows Event Logs, Sysmon captures rich telemetry that helps SOC analysts detect malicious behaviour early in the attack chain.

This repository documents a complete, hands‑on exploration of Sysmon from a defender’s perspective. It is based on practical investigations, real attacker techniques, and structured detection workflows aligned with SOC operations.

## Why Sysmon Matters

Modern attacks rarely rely on a single exploit. Instead, adversaries chain together multiple behaviours:
- Executing payloads  
- Injecting into legitimate processes  
- Establishing persistence  
- Dumping credentials  
- Communicating with command‑and‑control servers  
- Attempting to evade detection  

Sysmon provides the telemetry needed to observe these behaviours in detail. With the right configuration and analysis approach, it becomes one of the most valuable tools for Windows‑based threat detection.

## What This Section Covers

This introduction sets the foundation for the rest of the repository by explaining:
- What Sysmon is  
- Why it is essential for SOC analysts  
- How Sysmon fits into modern detection and response workflows  
- The types of events and behaviours Sysmon helps uncover  

The following sections build on this foundation, moving from installation and configuration to real‑world hunting, malware analysis, persistence detection, evasion techniques, and full investigation walkthroughs.

---

**Next:** [02 — Sysmon Overview](./02-sysmon-overview.md)

