# Sysmon Overview Architecture

This diagram provides a high‑level overview of how Sysmon operates inside Windows, how it captures telemetry, and how that data flows into a SIEM for SOC analysis.  
It visually explains the relationship between the Sysmon driver, Sysmon service, event IDs, and downstream log analysis.

## How to Read This Diagram
- **Blue** = Windows OS components  
- **Purple** = Sysmon components  
- **Green** = Telemetry output (Event IDs)  
- **Orange** = SIEM ingestion  
- **Grey** = SOC analysis  
- **Arrows** show the flow of data from system activity → Sysmon → SIEM → analyst.

```mermaid
flowchart TD

    %% STYLE DEFINITIONS
    classDef os fill:#4C9AFF,stroke:#1B4F72,color:#fff;
    classDef sysmon fill:#AF7AC5,stroke:#6C3483,color:#fff;
    classDef events fill:#58D68D,stroke:#1D8348,color:#fff;
    classDef siem fill:#F5B041,stroke:#B9770E,color:#fff;
    classDef soc fill:#AAB7B8,stroke:#626567,color:#fff;

    %% WINDOWS OS LAYER
    OS["Windows OS<br>Processes • Registry • Network • Drivers"]:::os

    %% SYSMON COMPONENTS
    Driver["Sysmon Driver<br>(Kernel Monitoring)"]:::sysmon
    Service["Sysmon Service<br>(User‑mode Processing)"]:::sysmon
    Config["Sysmon Config.xml<br>(Rules & Filters)"]:::sysmon

    %% EVENT OUTPUT
    Events["Sysmon Event IDs<br>1–28<br>(Process • File • Registry • Network • WMI • Tampering)"]:::events

    %% SIEM INGESTION
    SIEM["SIEM / Log Platform<br>(Elastic • Splunk • Sentinel)"]:::siem

    %% SOC ANALYSIS
    SOC["SOC Analyst<br>Hunting • Detection • IR"]:::soc

    %% FLOW CONNECTIONS
    OS --> Driver
    Driver --> Service
    Config --> Service
    Service --> Events
    Events --> SIEM
    SIEM --> SOC
