# 09 - Detecting Evasion Techniques

Attackers know defenders rely on telemetry from tools like Sysmon, so they often attempt to hide their activity by evading logging, blending in with legitimate processes, or abusing trusted system binaries.  
This section focuses on identifying those evasion behaviours using Sysmon’s high‑value event data.

Evasion is not about avoiding execution — it’s about avoiding *visibility*.  
Sysmon helps uncover these attempts by monitoring the underlying system behaviour attackers cannot easily hide.

---

## Why Evasion Matters

Even well‑designed detection rules can fail if attackers:

- Masquerade as legitimate processes  
- Disable or tamper with logging  
- Inject into trusted processes  
- Use LOLBINs to blend in  
- Obfuscate command lines  
- Execute payloads in memory  
- Avoid writing files to disk  

Evasion techniques are often subtle, but Sysmon captures the behavioural traces that reveal them.

---

## Key Sysmon Events for Detecting Evasion

### **Event ID 1 - Process Create**
Useful for spotting:
- Masquerading (fake filenames like `svch0st.exe`)  
- LOLBIN abuse (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`)  
- Encoded or obfuscated command lines  
- Suspicious parent/child chains  

Example:
```code
powershell.exe -nop -w hidden -enc <Base64>
```

---

### **Event ID 7 — Image Loaded**
Reveals:
- Unusual DLLs loaded into trusted processes  
- Reflective DLL injection  
- Malware loading modules directly into memory  

If a process like `explorer.exe` loads uncommon DLLs, it’s suspicious.

---

### **Event ID 8 — CreateRemoteThread**
A strong indicator of:
- Process injection  
- Malware hiding inside legitimate processes  
- Evasion through stealthy execution  

Example:
```code
malware.exe → injects into explorer.exe
```

---

### **Event ID 10 — Process Access**
Critical for detecting:
- Credential theft attempts  
- Token manipulation  
- Memory scraping  
- LSASS access  

Attackers often try to access LSASS without triggering obvious alerts.

---

### **Event ID 11 — File Create**
Useful for spotting:
- Dropped payloads disguised as system files  
- Files written to obscure directories  
- Temporary staging files  

Attackers may attempt to hide payloads in:
- `C:\Windows\Temp\`
- `C:\ProgramData\`
- AppData subfolders

---

### **Event ID 22 — DNS Query**
Evasion often involves:
- Domain‑generated algorithms (DGA)  
- Fast‑flux infrastructure  
- Suspicious or random‑looking domains  

Sysmon logs DNS queries with the process responsible.

---

## Common Evasion Techniques to Hunt For

### **1. Masquerading**
Attackers rename malware to look legitimate:
- `svch0st.exe`  
- `expl0rer.exe`  
- `chrome-updater.exe`  

Sysmon reveals the true path and parent process.

---

### **2. LOLBIN Abuse**
Living‑off‑the‑land binaries allow attackers to blend in:
- `mshta.exe`  
- `rundll32.exe`  
- `regsvr32.exe`  
- `wmic.exe`  
- `powershell.exe`  

These tools are legitimate but dangerous when misused.

---

### **3. In‑Memory Execution**
Attackers avoid writing files to disk by:
- Reflective DLL injection  
- PowerShell in‑memory modules  
- .NET assembly loading  

Sysmon detects the injection and module loading behaviour.

---

### **4. Obfuscation**
Examples include:
- Base64‑encoded PowerShell  
- Hidden windows (`-w hidden`)  
- No profile (`-nop`)  
- No logs (`-nol`)  

These flags are red flags.

---

### **5. Disabling or Tampering with Logging**
Attackers may attempt to:
- Stop Sysmon  
- Modify Sysmon configs  
- Clear event logs  

Sysmon logs the processes that attempt these actions.

---

## Practical Evasion Hunting Workflow

1. **Start with Event ID 1**  
   Look for suspicious command lines, LOLBIN abuse, or masquerading.

2. **Pivot to Event ID 7 / 8 / 10**  
   Identify injection, memory access, or unusual DLL loads.

3. **Check Event ID 22**  
   Look for suspicious DNS queries or DGA patterns.

4. **Review Event ID 11**  
   Identify disguised or hidden payloads.

5. **Map the evasion chain**  
   Determine how the attacker attempted to hide their activity.

This mirrors real SOC evasion investigations.

---

## Why Sysmon Is Effective Against Evasion

Even when attackers try to hide, they cannot avoid:
- Creating processes  
- Loading DLLs  
- Accessing memory  
- Making network connections  
- Modifying the registry  

Sysmon captures these behaviours, making evasion attempts detectable when monitored correctly.

---

**Next:** [10 - Practical Investigations](./10-practical-investigations.md)

