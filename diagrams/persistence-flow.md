# Persistence Detection Flow (Sysmon Event IDs)

This diagram illustrates how Sysmon detects common persistence mechanisms used by attackers, including registry autoruns, scheduled tasks, services, WMI event subscriptions, and Startup folder abuse.

## How to Read This Diagram
- **Orange nodes** = Registry‑based persistence  
- **Green nodes** = File‑based persistence  
- **Red nodes** = WMI persistence  
- **Grey nodes** = Service or configuration tampering  
- **Arrows** show the recommended SOC investigation path from initial execution → persistence mechanism → supporting evidence.

```mermaid
flowchart TD

    %% STYLE DEFINITIONS
    classDef process fill:#4C9AFF,stroke:#1B4F72,color:#fff;
    classDef registry fill:#F5B041,stroke:#B9770E,color:#fff;
    classDef file fill:#58D68D,stroke:#1D8348,color:#fff;
    classDef wmi fill:#EC7063,stroke:#943126,color:#fff;
    classDef config fill:#AAB7B8,stroke:#626567,color:#fff;

    %% START OF PERSISTENCE HUNT
    Start["Start Persistence Hunt<br>Identify Suspicious Autoruns"]:::process

    %% REGISTRY PERSISTENCE
    E13["Event ID 13<br>Registry Value Set<br>(Run Keys, Services)"]:::registry
    E12["Event ID 12<br>Registry Key Added/Deleted"]:::registry
    E14["Event ID 14<br>Registry Key Renamed"]:::registry

    %% FILE-BASED PERSISTENCE
    E11["Event ID 11<br>File Create<br>(Startup Folder, Scripts)"]:::file
    E2["Event ID 2<br>Timestomp<br>(Modified Creation Time)"]:::file

    %% WMI PERSISTENCE
    E19["Event ID 19<br>WMI Event Filter"]:::wmi
    E20["Event ID 20<br>WMI Event Consumer"]:::wmi
    E21["Event ID 21<br>WMI Filter-to-Consumer Binding"]:::wmi

    %% SERVICE / CONFIG TAMPERING
    E4["Event ID 4<br>Sysmon Service State Changed"]:::config
    E16["Event ID 16<br>Sysmon Config Change"]:::config

    %% FLOW CONNECTIONS
    Start --> E13
    Start --> E11
    Start --> E19

    E13 --> E12
    E13 --> E14

    E11 --> E2

    E19 --> E20 --> E21

    E21 --> E4
    E21 --> E16
