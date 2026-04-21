# Process Injection Flow (Sysmon Event IDs)

This diagram illustrates how Sysmon detects process injection techniques such as process hollowing, remote thread creation, token manipulation, and DLL injection.  
It shows the investigative flow analysts follow when suspicious memory‑level activity occurs.

## How to Read This Diagram
- **Red nodes** = Injection‑related Sysmon events  
- **Blue nodes** = Process creation context  
- **Purple nodes** = Image/DLL load indicators  
- **Grey nodes** = Evasion or tampering  
- **Arrows** show the typical SOC investigation path from initial execution → access → injection → tampering.

```mermaid
flowchart TD

    %% STYLE DEFINITIONS
    classDef process fill:#4C9AFF,stroke:#1B4F72,color:#fff;
    classDef injection fill:#EC7063,stroke:#943126,color:#fff;
    classDef image fill:#AF7AC5,stroke:#6C3483,color:#fff;
    classDef tamper fill:#AAB7B8,stroke:#626567,color:#fff;

    %% PROCESS CREATION
    E1["Event ID 1<br>Process Create"]:::process

    %% ACCESS & INJECTION
    E10["Event ID 10<br>Process Access"]:::injection
    E8["Event ID 8<br>CreateRemoteThread"]:::injection
    E25["Event ID 25<br>Process Tampering"]:::tamper

    %% IMAGE / DLL LOADS
    E7["Event ID 7<br>Image Loaded (DLL Load)"]:::image

    %% RAW READS (Rootkits / Memory Tools)
    E9["Event ID 9<br>RawAccessRead"]:::tamper

    %% FLOW CONNECTIONS
    E1 --> E10
    E10 --> E8
    E8 --> E25
    E10 --> E7
    E7 --> E25
    E25 --> E9
