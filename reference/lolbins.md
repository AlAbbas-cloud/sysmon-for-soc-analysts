# Windows LOLBIN Reference (Living‑Off‑The‑Land Binaries)

Living‑off‑the‑land binaries (LOLBINs) are legitimate Windows executables that attackers abuse to execute malicious code, bypass security controls, download payloads, or establish persistence.

This reference lists the most commonly abused LOLBINs, the Sysmon events that detect them, and their MITRE ATT&CK mappings.

Use this file during:
- Threat hunting  
- Detection engineering  
- Malware investigations  
- Process chain analysis  
- SOC triage  

---

# Quick LOLBIN Table

| LOLBIN | Purpose | Common Abuse | Sysmon Events | MITRE Techniques |
|--------|---------|--------------|----------------|------------------|
| **powershell.exe** | Automation & scripting | Payload execution, downloaders, in‑memory attacks | 1, 3, 7, 10 | T1059.001, T1105, T1055 |
| **cmd.exe** | Command interpreter | Staging, launching payloads | 1 | T1059.003 |
| **mshta.exe** | Executes HTA files | Remote payload execution | 1, 3, 11 | T1218.005 |
| **rundll32.exe** | Runs DLL exports | Malware execution, LOLBAS | 1, 7 | T1218.011 |
| **regsvr32.exe** | Registers DLLs | Squiblydoo, remote script execution | 1, 3, 7 | T1218.010 |
| **wmic.exe** | WMI interface | Lateral movement, remote execution | 1, 3 | T1047 |
| **wscript.exe / cscript.exe** | Script hosts | VBS/JScript malware | 1, 11 | T1059.005 |
| **bitsadmin.exe** | Background downloader | Payload download | 1, 3 | T1197 |
| **certutil.exe** | Certificate utility | Downloading, decoding payloads | 1, 11 | T1105, T1140 |
| **msiexec.exe** | Installer engine | Remote MSI execution | 1, 3 | T1218.007 |
| **schtasks.exe** | Task scheduler | Persistence | 1, 11, 13 | T1053.005 |
| **sc.exe** | Service control | Persistence, privilege escalation | 1, 13 | T1543 |
| **at.exe** | Legacy scheduler | Persistence | 1 | T1053 |
| **ftp.exe** | File transfer | Payload download | 1, 3 | T1105 |
| **curl.exe / wget.exe** | Download tools | Payload retrieval | 1, 3 | T1105 |
| **msbuild.exe** | Build engine | Fileless malware | 1, 7 | T1127 |
| **installutil.exe** | Installer utility | Execute malicious assemblies | 1 | T1218.004 |
| **dnscmd.exe** | DNS management | DNS exfiltration | 1, 22 | T1048 |
| **net.exe / net1.exe** | Admin commands | User/group enumeration | 1 | T1087 |
| **whoami.exe** | Identity query | Reconnaissance | 1 | T1033 |

---

# 🔍 Detailed LOLBIN Breakdown

Below is a deeper SOC‑focused explanation of each LOLBIN, how attackers abuse it, and how Sysmon detects it.

---

## **powershell.exe**
**Abuse:**  
- Encoded commands  
- In‑memory payloads  
- Download‑execute chains  
- Reflective PE injection  

**Sysmon:** 1, 3, 7, 10  
**MITRE:** T1059.001, T1105, T1055  

---

## **cmd.exe**
**Abuse:**  
- Launching LOLBINs  
- Dropping payloads  
- Staging commands  

**Sysmon:** 1  
**MITRE:** T1059.003  

---

## **mshta.exe**
**Abuse:**  
- Executes remote HTA payloads  
- Runs JavaScript/VBScript  
- Used in phishing chains  

**Sysmon:** 1, 3, 11  
**MITRE:** T1218.005  

---

## **rundll32.exe**
**Abuse:**  
- Executes DLL exports  
- Runs JavaScript via `mshtml.dll`  
- Fileless malware  

**Sysmon:** 1, 7  
**MITRE:** T1218.011  

---

## **regsvr32.exe**
**Abuse:**  
- Squiblydoo technique  
- Executes remote scripts  
- Bypasses application whitelisting  

**Sysmon:** 1, 3, 7  
**MITRE:** T1218.010  

---

## **wmic.exe**
**Abuse:**  
- Remote command execution  
- Reconnaissance  
- Lateral movement  

**Sysmon:** 1, 3  
**MITRE:** T1047  

---

## **wscript.exe / cscript.exe**
**Abuse:**  
- Executes VBS/JScript malware  
- Fileless loaders  

**Sysmon:** 1, 11  
**MITRE:** T1059.005  

---

## **bitsadmin.exe**
**Abuse:**  
- Downloading payloads  
- C2 communication  

**Sysmon:** 1, 3  
**MITRE:** T1197  

---

## **certutil.exe**
**Abuse:**  
- Downloading files  
- Base64 decoding malware  
- Certificate store abuse  

**Sysmon:** 1, 11  
**MITRE:** T1105, T1140  

---

## **msiexec.exe**
**Abuse:**  
- Executes remote MSI packages  
- Runs malicious installers  

**Sysmon:** 1, 3  
**MITRE:** T1218.007  

---

## **schtasks.exe**
**Abuse:**  
- Persistence  
- Scheduled execution of payloads  

**Sysmon:** 1, 11, 13  
**MITRE:** T1053.005  

---

## **sc.exe**
**Abuse:**  
- Create/modify services  
- Persistence  
- Privilege escalation  

**Sysmon:** 1, 13  
**MITRE:** T1543  

---

## **curl.exe / wget.exe**
**Abuse:**  
- Downloading payloads  
- Fetching C2 commands  

**Sysmon:** 1, 3  
**MITRE:** T1105  

---

## **msbuild.exe**
**Abuse:**  
- Executes malicious XML project files  
- Fileless malware loaders  

**Sysmon:** 1, 7  
**MITRE:** T1127  

---

## **installutil.exe**
**Abuse:**  
- Executes malicious .NET assemblies  
- Bypasses application controls  

**Sysmon:** 1  
**MITRE:** T1218.004  

---

## **dnscmd.exe**
**Abuse:**  
- DNS exfiltration  
- DNS record manipulation  

**Sysmon:** 1, 22  
**MITRE:** T1048  

---

## **net.exe / net1.exe**
**Abuse:**  
- User/group enumeration  
- Privilege escalation prep  

**Sysmon:** 1  
**MITRE:** T1087  

---

## **whoami.exe**
**Abuse:**  
- Identity reconnaissance  

**Sysmon:** 1  
**MITRE:** T1033  

---

# ✔ This file is now complete and ready for your repo.

