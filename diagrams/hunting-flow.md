# Sysmon Hunting Flow

This diagram illustrates a practical SOC hunting workflow using Sysmon telemetry.  
It shows how analysts pivot between key event IDs to uncover malicious behaviour, reconstruct attack chains, and identify persistence, injection, or C2 activity.

## How to Read This Diagram
- **Arrows** represent the recommended investigation path.  
- **Colours** represent Sysmon event categories.  
- Start at **Process Creation (Event ID 1)** and follow the flow as suspicious behaviour emerges.  
- This mirrors real SOC triage and threat‑hunting methodology.

```mermaid
flowchart TD

    %% STYLE DEFINITIONS
    classDef process fill:#4C9AFF,stroke:#1B4F72,color:#fff;
    classDef file fill:#58D68D,stroke:#1D8348,color:#fff;
    classDef registry fill:#F5B041,stroke:#B9770E,color:#fff;
    classDef network fill:#AF7AC5,stroke:#6C3483,color:#fff;
    classDef injection fill:#EC7063,stroke:#943126,color:#fff;
    classDef wmi fill:#F1948A,stroke:#922B21,color:#fff;
    classDef config fill:#AAB7B8,stroke:#626567,color:#fff;

    %% START OF HUNT
    Start["Start Hunt<br>Identify Suspicious Activity"]:::process

    %% PROCESS EVENTS
    E1["Event ID 1<br>Process Create"]:::process
    E10["Event ID 10<br>Process Access"]:::injection
    E8["Event ID 8<br>CreateRemoteThread"]:::injection

    %% FILE EVENTS
    E11["Event ID 11<br>File Create"]:::file
    E15["Event ID 15<br>ADS Creation"]:::file

    %% REGISTRY EVENTS
    E13["Event ID 13<br>Registry Value Set"]:::registry

    %% NETWORK EVENTS
    E3["Event ID 3<br>Network Connection"]:::network
    E22["Event ID 22<br>DNS Query"]:::network

    %% WMI EVENTS
    E19["Event ID 19–21<br>WMI Persistence"]:::wmi

    %% CONFIG EVENTS
    E4["Event ID 4<br>Sysmon Service State Changed"]:::config
    E16["Event ID 16<br>Sysmon Config Change"]:::config

    %% FLOW CONNECTIONS
    Start --> E1
    E1 --> E11
    E1 --> E10
    E1 --> E3

    E11 --> E13
    E11 --> E15

    E10 --> E8

    E3 --> E22
    E3 --> E19

    E19 --> E4
    E19 --> E16
