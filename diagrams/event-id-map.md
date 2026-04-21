# Sysmon Event ID Map

This diagram visually groups all Sysmon Event IDs by category, making it easy for analysts to understand the telemetry landscape at a glance.  
It provides a high‑level overview of how Sysmon structures its telemetry across process, file, registry, network, WMI, and configuration events.

## How to Read This Diagram
- Each **colour** represents a Sysmon event category.  
- **Arrows** show the typical investigative flow (Process → File → Registry → Network → WMI → Config).  
- Use this map to quickly identify which events matter during threat hunting or incident response.

```mermaid
flowchart LR

    %% STYLE DEFINITIONS
    classDef process fill:#4C9AFF,stroke:#1B4F72,color:#fff;
    classDef file fill:#58D68D,stroke:#1D8348,color:#fff;
    classDef registry fill:#F5B041,stroke:#B9770E,color:#fff;
    classDef network fill:#AF7AC5,stroke:#6C3483,color:#fff;
    classDef image fill:#5DADE2,stroke:#2E86C1,color:#fff;
    classDef wmi fill:#F1948A,stroke:#922B21,color:#fff;
    classDef pipe fill:#85C1E9,stroke:#2E86C1,color:#fff;
    classDef config fill:#AAB7B8,stroke:#626567,color:#fff;

    %% ===========================
    %%   PROCESS EVENTS
    %% ===========================
    subgraph PROCESS_EVENTS[Process Events]
        E1["1 — Process Create"]:::process
        E5["5 — Process Terminated"]:::process
        E8["8 — CreateRemoteThread"]:::process
        E10["10 — Process Access"]:::process
        E25["25 — Process Tampering"]:::process
    end

    %% ===========================
    %%   FILE EVENTS
    %% ===========================
    subgraph FILE_EVENTS[File Events]
        E2["2 — File Creation Time Changed"]:::file
        E11["11 — File Create"]:::file
        E15["15 — FileCreateStreamHash (ADS)"]:::file
        E23["23 — File Delete (Archived)"]:::file
        E26["26 — File Delete"]:::file
        E27["27 — File Block Executable"]:::file
        E28["28 — File Block Shredding"]:::file
    end

    %% ===========================
    %%   REGISTRY EVENTS
    %% ===========================
    subgraph REGISTRY_EVENTS[Registry Events]
        E12["12 — Registry Object Added/Deleted"]:::registry
        E13["13 — Registry Value Set"]:::registry
        E14["14 — Registry Object Renamed"]:::registry
    end

    %% ===========================
    %%   NETWORK EVENTS
    %% ===========================
    subgraph NETWORK_EVENTS[Network Events]
        E3["3 — Network Connection"]:::network
        E22["22 — DNS Query"]:::network
    end

    %% ===========================
    %%   DRIVER & IMAGE EVENTS
    %% ===========================
    subgraph IMAGE_DRIVER_EVENTS[Driver & Image Events]
        E6["6 — Driver Loaded"]:::image
        E7["7 — Image Loaded"]:::image
        E9["9 — RawAccessRead"]:::image
    end

    %% ===========================
    %%   WMI EVENTS
    %% ===========================
    subgraph WMI_EVENTS[WMI Persistence Events]
        E19["19 — WMI Event Filter"]:::wmi
        E20["20 — WMI Event Consumer"]:::wmi
        E21["21 — WMI Filter-to-Consumer Binding"]:::wmi
    end

    %% ===========================
    %%   PIPE EVENTS
    %% ===========================
    subgraph PIPE_EVENTS[Named Pipe Events]
        E17["17 — Pipe Created"]:::pipe
        E18["18 — Pipe Connected"]:::pipe
    end

    %% ===========================
    %%   CONFIG EVENTS
    %% ===========================
    subgraph CONFIG_EVENTS[Sysmon Configuration Events]
        E4["4 — Sysmon Service State Changed"]:::config
        E16["16 — Sysmon Configuration Change"]:::config
    end

    %% DIRECTIONAL FLOW (Investigation Path)
    E1 --> E11 --> E13 --> E3 --> E19 --> E4
