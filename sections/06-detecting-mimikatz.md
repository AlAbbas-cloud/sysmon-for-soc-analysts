# 06 — Detecting Mimikatz

Mimikatz is one of the most widely used tools for credential theft on Windows systems.  
Attackers use it to extract passwords, hashes, Kerberos tickets, and other sensitive authentication material directly from memory.

Because Mimikatz interacts with LSASS (Local Security Authority Subsystem Service), it leaves behind highly suspicious behavioural traces — and Sysmon is excellent at detecting them.

This section focuses on identifying those traces using key Sysmon events.

---

## What Mimikatz Does

Mimikatz enables attackers to:

- Dump plaintext passwords  
- Extract NTLM hashes  
- Steal Kerberos tickets (Pass‑the‑Ticket)  
- Perform Pass‑the‑Hash attacks  
- Manipulate authentication tokens  
- Interact directly with LSASS memory  

These actions require elevated privileges and direct access to sensitive system processes, making them detectable with the right telemetry.

---

## Key Sysmon Events for Detecting Mimikatz

### **Event ID 10 — Process Access**
This is the most important event for detecting Mimikatz.

It logs when one process attempts to access another process’s memory.  
Mimikatz must access **LSASS.exe**, so look for:

- A non‑system process accessing LSASS  
- Suspicious access rights (e.g., `0x1010`, `0x1410`, `0x1F0FFF`)  
- Tools like PowerShell, cmd.exe, or unknown EXEs touching LSASS  

Example suspicious pattern:
```code
SourceImage: powershell.exe
TargetImage: lsass.exe
GrantedAccess: 0x1F0FFF
```

This is a classic Mimikatz indicator.

---

### **Event ID 1 — Process Create**
Useful for spotting:

- Execution of known Mimikatz binaries  
- LOLBIN‑based credential theft  
- Suspicious command lines  
- Unusual parent/child relationships  

Common Mimikatz execution methods include:

- `mimikatz.exe` (obvious but still seen)
- PowerShell scripts loading Mimikatz modules
- Encoded PowerShell commands
- Dropped EXEs in temp directories

---

### **Event ID 7 — Image Loaded**
Mimikatz often loads:

- `sekurlsa.dll`
- Other credential‑related modules

If a non‑system process loads credential‑handling DLLs, it’s a red flag.

---

## Common Indicators of Mimikatz Activity

### **1. LSASS Access**
Any non‑system process accessing LSASS is suspicious.

### **2. High‑Privilege Access Rights**
Mimikatz requires full memory access rights (`0x1F0FFF`).

### **3. Suspicious Process Names**
Attackers often rename Mimikatz to evade detection:
- `mimi.exe`
- `mktz.exe`
- `debug.exe`
- `test.exe`

### **4. PowerShell‑Based Credential Theft**
Examples:
```code
Invoke-Mimikatz
Invoke-ReflectivePEInjection
```

### **5. Execution from Unusual Locations**
Mimikatz is often run from:
- `%TEMP%`
- `%APPDATA%`
- Downloads
- Desktop
- Public folders

---

## Practical Hunting Workflow

1. **Start with Event ID 10**  
   Look for LSASS access attempts.

2. **Pivot to Event ID 1**  
   Identify the process responsible.

3. **Check Event ID 7**  
   Look for credential‑related DLLs being loaded.

4. **Review command lines**  
   Look for encoded commands or suspicious modules.

5. **Map the attack chain**  
   Determine how the attacker executed Mimikatz and what they did next.

This mirrors real SOC credential‑theft investigations.

---

## Why Sysmon Is Effective Against Mimikatz

Mimikatz cannot operate without:
- Accessing LSASS  
- Loading credential‑related modules  
- Running with elevated privileges  

Sysmon logs all of these behaviours, making Mimikatz activity highly detectable when properly monitored.

---

**Next:** [07 — Hunting Malware](./07-hunting-malware.md)
