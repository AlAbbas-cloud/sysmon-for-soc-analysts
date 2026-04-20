# 03 - Installing and Preparing Sysmon

Before Sysmon can begin collecting high‑value telemetry, it must be installed and configured with a proper ruleset. This section covers the installation process, configuration files, and how to verify that Sysmon is running correctly.

Sysmon installation is straightforward, but the configuration you choose determines the quality of the logs you receive. A good config turns Sysmon into a powerful detection sensor; a bad config turns it into noise.

---

## Downloading Sysmon

Sysmon is part of the Microsoft Sysinternals Suite and can be downloaded from the official Microsoft website. The download includes:

- `Sysmon.exe` (32‑bit)
- `Sysmon64.exe` (64‑bit)
- Documentation
- EULA

Most modern systems will use **Sysmon64.exe**.

---

## Installing Sysmon with a Configuration File

Sysmon requires a configuration file to define what events it should capture. Without a config, Sysmon logs very little.

Two widely used community configurations are:

- **SwiftOnSecurity’s sysmon-config**  
  A well‑maintained, noise‑reduced, enterprise‑friendly config.

- **ION‑Storm’s config**  
  More verbose, useful for labs and deep investigations.

To install Sysmon with a config:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```
**This command:**

- Accepts the license agreement
- Installs the Sysmon driver
- Applies the configuration
- Starts the Sysmon service
  
---
## Verifying Sysmon Installation
**Once installed, Sysmon logs appear in:**
```code
Event Viewer
  → Applications and Services Logs
    → Microsoft
      → Windows
        → Sysmon
          → Operational
```
**You should see events such as:**

- Event ID 1 - Process Create
- Event ID 3 - Network Connection
- Event ID 11 - File Create
- Event ID 22 - DNS Query

If these events are present, Sysmon is running correctly.

---
## Updating the Configuration
**Sysmon allows live configuration updates without reinstalling:**
```powershell
Sysmon64.exe -c sysmonconfig.xml
```
This is useful when tuning noise, adding new detection rules, or enabling additional event types.

---
## Uninstalling Sysmon
**If Sysmon needs to be removed:**
```powershell
Sysmon64.exe -u
```
This cleanly removes the service and driver.

---
## What This Section Enables
**By completing this stage, you now have:**

- A working Sysmon installation
- A tuned configuration file
- A live event stream ready for hunting

**Next:** [03 - cutting-noise](./04-cutting-noise.md)
- The foundation for all detection and investigation work in later sections

The next section focuses on reducing noise and tuning Sysmon for real‑world SOC environments.
