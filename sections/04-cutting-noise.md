# 04 — Cutting Out the Noise

Sysmon is powerful, but without proper tuning it can generate thousands of events per minute.  
In a real SOC environment, this level of noise makes it difficult to identify meaningful attacker behaviour.  
This section focuses on reducing unnecessary logs so analysts can focus on high‑value telemetry.

Noise reduction is not about hiding data — it’s about filtering out routine, harmless system activity so that suspicious behaviour stands out clearly.

---

## Why Noise Reduction Matters

Windows systems generate constant background activity:
- Legitimate processes starting and stopping  
- System services communicating internally  
- Routine file and registry operations  
- Background network traffic  

If every one of these events is logged, analysts drown in data.  
Noise reduction ensures that Sysmon captures **signal, not clutter**.

---

## Using a Good Configuration File

The Sysmon configuration file determines:
- Which events are logged  
- Which events are ignored  
- What filters are applied  
- How much detail is captured  

A well‑tuned config:
- Removes repetitive system noise  
- Focuses on attacker techniques  
- Reduces storage and processing overhead  
- Makes investigations faster and clearer  

Community configs such as **SwiftOnSecurity’s sysmon-config** are widely used because they strike a balance between visibility and noise reduction.

---

## Filtering Out Known‑Good Activity

Sysmon supports include/exclude rules that allow you to filter events based on:
- Image names  
- Parent processes  
- File paths  
- Command lines  
- Hashes  
- Network destinations  

Examples of noise you typically filter out:
- Windows Update  
- Chrome/Edge routine connections  
- System32 background processes  
- Trusted services like svchost.exe performing normal tasks  

By excluding predictable, benign behaviour, you highlight anomalies.

---

## Focusing on High‑Value Events

Not all Sysmon events are equally useful.  
For threat hunting, the most valuable events include:

- **Event ID 1 — Process Create**  
- **Event ID 3 — Network Connection**  
- **Event ID 7 — Image Loaded**  
- **Event ID 8 — CreateRemoteThread**  
- **Event ID 10 — Process Access**  
- **Event ID 11 — File Create**  
- **Event ID 13 — Registry Value Set**  
- **Event ID 15 — FileCreateStreamHash**  
- **Event ID 22 — DNS Query**

These events reveal:
- Malware execution  
- Credential theft  
- Lateral movement  
- Persistence  
- Process injection  
- C2 communication  
- Evasion attempts  

Noise reduction ensures these events stand out.

---

## Practical Impact in a SOC

A tuned Sysmon deployment allows analysts to:
- Detect attacks earlier  
- Investigate incidents faster  
- Reduce alert fatigue  
- Improve detection engineering  
- Focus on behaviour, not background noise  

Noise reduction is one of the most important steps in making Sysmon operationally useful.

---

**Next:** [05 — Hunting Metasploit](./05-hunting-metasploit.md)

