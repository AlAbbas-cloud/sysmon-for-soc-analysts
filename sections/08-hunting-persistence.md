# 08 - Hunting Persistence

Persistence is the attacker’s way of ensuring continued access to a compromised system.  
Even if the initial malware is removed or the system is rebooted, persistence mechanisms allow the attacker to return without repeating the initial intrusion.

Sysmon provides visibility into many of the most common persistence techniques used in real attacks.  
This section focuses on identifying those behaviours using high‑value Sysmon events.

---

## Why Persistence Matters

Attackers rarely rely on a single execution.  
Once inside a system, they typically:

- Create scheduled tasks  
- Modify registry autoruns  
- Install services  
- Drop payloads into startup folders  
- Use WMI event subscriptions  
- Abuse LOLBINs for stealthy execution  

Persistence is often subtle, but Sysmon captures the underlying system changes that reveal it.

---

## Key Sysmon Events for Persistence Detection

### **Event ID 1 - Process Create**
Useful for spotting:
- Creation of scheduled tasks (`schtasks.exe`)  
- Registry modification tools (`reg.exe`, `powershell.exe`)  
- LOLBIN‑based persistence (e.g., `mshta.exe`, `rundll32.exe`)  

Example:
```code
schtasks.exe /Create /TN Updater /TR <payload>
```

---

### **Event ID 11 - File Create**
Persistence often involves writing files to:
- Startup folders  
- Scheduled task directories  
- AppData  
- ProgramData  

Example from an investigation:
```code
C:\Windows\System32\Tasks\Updater
```
This indicates a scheduled task being created.

---

### **Event ID 13 - Registry Value Set**
Critical for detecting:
- Run keys  
- RunOnce keys  
- Script execution entries  
- COM hijacking  
- Service configuration changes  

Common persistence registry paths:
```code
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

---

### **Event ID 12 & 14 - Registry Object Create/Delete**
Useful for:
- Tracking new autorun keys  
- Detecting removal or replacement of legitimate entries  

---

### **Event ID 7 - Image Loaded**
Some persistence mechanisms load DLLs into:
- Explorer  
- Winlogon  
- Services  

Unexpected DLLs in these processes are suspicious.

---

### **Event ID 3 - Network Connection**
Persistence mechanisms may beacon out after reboot.  
Look for:
- Outbound connections shortly after system startup  
- Connections from unusual processes  

---

## Common Persistence Techniques to Hunt For

### **1. Scheduled Tasks**
Attackers create tasks that run:
- At logon  
- At startup  
- On a timer  

Sysmon logs both the file creation and the process that created it.

---

### **2. Registry Autoruns**
Malware frequently adds entries to:
- Run keys  
- RunOnce keys  
- Shell extensions  

Sysmon Event ID 13 captures these modifications.

---

### **3. Startup Folder Payloads**
Files dropped into:
```bash
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

---

### **4. Services**
Attackers may install or modify services to run malicious binaries.

Indicators include:
- `sc.exe` usage  
- Registry modifications under `Services` keys  

---

### **5. WMI Persistence**
More advanced attackers use:
- WMI event filters  
- WMI consumers  
- WMI bindings  

Sysmon can detect the processes that create these entries.

---

## Practical Persistence Hunting Workflow

1. **Start with Event ID 13**  
   Look for registry autorun modifications.

2. **Pivot to Event ID 1**  
   Identify the process responsible for creating persistence.

3. **Check Event ID 11**  
   Look for payloads dropped into startup or scheduled task directories.

4. **Review Event ID 3**  
   Identify any beaconing behaviour after reboot.

5. **Map the persistence chain**  
   Determine how the attacker ensured long‑term access.

This workflow mirrors real SOC investigations.

---

## Why Sysmon Is Effective Against Persistence

Persistence requires:
- File creation  
- Registry modification  
- Process execution  
- System configuration changes  

Sysmon logs all of these actions, making persistence techniques highly detectable when monitored correctly.

---

**Next:** [09 - Detecting Evasion Techniques](./09-detecting-evasion.md)
