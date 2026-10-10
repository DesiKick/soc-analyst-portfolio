# Lab 01: Windows Telemetry & Process Creation Auditing (Event ID 4688)

- **Date:** October 2026
- **Category:** Endpoint Telemetry & Incident Analysis
- **Framework Mapping:** MITRE ATT&CK [T1059 - Command and Scripting Interpreter] / [T1082 - System Information Discovery]
- **Target OS:** Windows 10/11 Enterprise

---

## 1. Executive Summary & Objective
Adversaries routinely execute native binaries (Living off the Land) to enumerate accounts, query network configurations, and spawn malicious payloads. By default, Windows does not log granular process execution data. 

The objective of this lab was to configure **Audit Process Creation** within the Local Security Policy, generate process execution telemetry, and analyze the resulting **Event ID 4688** forensic artifacts to understand parent-child process relationships.

---

## 2. Methodology & Configuration
1. **Auditing Policy Configuration:**
   - Navigated to `Advanced Audit Policy Configuration` > `System Audit Policies` > `Detailed Tracking`.
   - Enabled **Audit Process Creation** for both **Success** and **Failure**.
2. **Log Acquisition:**
   - Monitored the `Security` event log via Windows Event Viewer (`eventvwr.msc`).
   - Filtered telemetry using event filter `EventID == 4688`.

---

## 3. Forensic Evidence & Artifact Analysis

### Telemetry Overview: Filtered Security Event Stream
![Windows Security Event Log Filter](../assets/images/lab01-event-overview.png)

### Granular Process Details: Parent-Child Lineage
![Windows Event ID 4688 Process Creation](../assets/images/lab01-event-4688.png)

### Key Artifact Breakdown:
- **Event ID:** `4688` (A new process has been created)
- **Account / Security ID:** `SYSTEM` (Authority/System-level context)
- **New Process Name:** `C:\Windows\System32\svchost.exe` (The spawned binary)
- **Creator (Parent) Process Name:** `C:\Windows\System32\services.exe` (The launching binary)
- **Mandatory Label:** `System Mandatory Level` (High integrity execution token)

### Analytical Insight:
In a typical enterprise SOC environment, mapping the **Parent Process** (`Creator Process Name`) to the **Child Process** (`New Process Name`) establishes the process lineage. While `services.exe` spawning `svchost.exe` represents expected baseline activity, an anomalous parent (such as `winword.exe` spawning `cmd.exe` or `powershell.exe`) would represent a high-confidence indicator of compromise (IOC) indicative of macro exploitation.

---

## 4. Defensive Takeaways for SOC Triage
- **Baseline Profiling:** Knowing what *should* launch a process is just as important as knowing what the binary does. Legitimate system binaries executing under abnormal parents must be flagged immediately.
- **Log Enrichment:** Standard 4688 logging provides binary names, but enabling the sub-setting *"Include command line in process creation events"* adds the full CLI arguments, essential for identifying obfuscated scripts (e.g., base64-encoded PowerShell).