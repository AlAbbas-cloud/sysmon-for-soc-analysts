# 05 - Hunting Metasploit

Metasploit is one of the most widely used offensive frameworks for gaining initial access, establishing reverse shells, and interacting with compromised systems.  
From a defender’s perspective, Metasploit activity leaves behind a series of behavioural indicators that Sysmon captures extremely well.

This section focuses on identifying those behaviours using high‑value Sysmon events.

---

## Understanding Metasploit Behaviour

Metasploit payloads commonly exhibit:

- Reverse TCP connections back to the attacker  
- Execution of payload stagers (PowerShell, mshta, rundll32, etc.)  
- Unusual parent/child process chains  
- Suspicious command‑line arguments  
- Network connections to uncommon ports (e.g., 4444, 5555)  
- File creation or staging of encoded payloads  

Sysmon provides visibility into all of these behaviours.

---

## Key Sysmon Events for Detecting Metasploit

### **Event ID 1 — Process Create**
Reveals:
- The payload execution method  
- Parent/child relationships  
- Command‑line arguments  
- LOLBIN abuse (e.g., `powershell.exe`, `mshta.exe`, `rundll32.exe`)  

Metasploit often spawns:
- PowerShell with encoded commands  
- mshta executing remote or local HTA payloads  
- cmd.exe running staging commands  

---

### **Event ID 3 — Network Connection**
Critical for identifying:
- Reverse shells  
- Meterpreter sessions  
- C2 callbacks  

Look for:
- Outbound connections to unusual ports (4444, 5555)  
- Connections to internal attacker IPs  
- Processes that normally should not make network connections  

Example suspicious pattern:
```powershell
powershell.exe → 10.0.2.18:4444
```

---

### **Event ID 11 — File Create**
Useful for spotting:
- Dropped payloads  
- Stagers written to disk  
- Temporary files used for execution  

Metasploit often writes:
- Encoded payloads  
- HTA files  
- DLLs or EXEs used for staging  

---

## Common Indicators of Metasploit Activity

### **1. Unusual Process Chains**
Examples:
- `winword.exe` → `powershell.exe`  
- `mshta.exe` → reverse shell  
- `cmd.exe` → PowerShell with Base64 payload  

### **2. Encoded PowerShell Commands**
Metasploit frequently uses:
```powershell
powershell.exe -enc <Base64>
```

---

### **3. Reverse TCP Connections**
Outbound connections to:
- High ports  
- Non‑standard destinations  
- Internal attacker machines  

### **4. Suspicious File Drops**
Payloads often appear in:
- `%TEMP%`
- `%APPDATA%`
- `%LOCALAPPDATA%`
- `Downloads`
- `C:\Windows\Temp\`

---

## Practical Hunting Workflow

1. **Start with Event ID 3**  
   Identify suspicious outbound connections.

2. **Pivot to Event ID 1**  
   Determine which process created the connection.

3. **Check Event ID 11**  
   Look for payloads or staging files.

4. **Review command lines**  
   Look for encoded commands, LOLBIN abuse, or HTA execution.

5. **Map the attack chain**  
   Reconstruct the sequence from initial execution → payload → network connection.

This mirrors real SOC investigation workflows.

---

## Why Sysmon Is Effective Against Metasploit

Metasploit relies heavily on:
- Process execution  
- Network callbacks  
- Staging payloads  
- Scripted execution  

Sysmon logs all of these behaviours with high fidelity, making it extremely difficult for Metasploit to operate without leaving traces.

---

**Next:** [06 — Detecting Mimikatz](./06-detecting-mimikatz.md)

