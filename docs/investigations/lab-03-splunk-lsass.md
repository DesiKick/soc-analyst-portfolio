# Lab 03: SIEM Threat Hunting & LSASS Credential Dumping Detection

- **Date:** October 2026
- **Category:** SIEM Detection Engineering & Threat Hunting
- **Framework Mapping:** MITRE ATT&CK [T1003.001 - OS Credential Dumping: LSASS Memory] / [TA0006 - Credential Access]
- **Tooling:** Splunk Enterprise, Search Processing Language (SPL), Sysmon (Event ID 10)

---

## 1. Executive Summary & Objective
Local Security Authority Subsystem Service (`lsass.exe`) enforces security policy and stores active authentication credentials, Kerberos tickets, and NTLM hashes in process memory. Adversaries routinely target LSASS to harvest credentials for domain-wide lateral movement.

The objective of this investigation was to ingest high-fidelity endpoint security telemetry into Splunk, build regular expression field extractions against raw Sysmon XML, and engineer a robust detection query (SPL) that exposes unauthorized attempts to access and dump LSASS memory.

---

## 2. Telemetry & Attack Surface
- **Data Source:** Sysmon Operational Logs (`Microsoft-Windows-Sysmon`)
- **Event ID:** `10` (ProcessAccess)
- **Target Process:** `C:\Windows\System32\lsass.exe`
- **Simulated Adversary:** Atomic Red Team (`T1003.001`)

---

## 3. Threat Hunting & SPL Engineering

### Phase 1: Ingestion & Telemetry Exploration
An initial hunt query across the dedicated `botsv1` index isolated all events referencing the LSASS credential vault:

```spl
index=botsv1 "lsass.exe"