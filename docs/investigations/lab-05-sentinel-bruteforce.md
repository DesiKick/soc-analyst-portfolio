---
title: 'Lab 05: Brute Force Detection in Microsoft Sentinel'
---

# Lab 05: Windows Authentication & Brute Force Detection in Microsoft Sentinel (KQL)

<div class="lab-meta" markdown>
**Category:** Cloud SIEM & Identity Detection Engineering<br>
**ATT&CK:** [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | TA0006 Credential Access<br>
**Platform:** Microsoft Sentinel / Azure Log Analytics Workspace<br>
**Telemetry:** Windows Security Event Log (Event IDs 4625, 4624 via Azure Monitor Agent)<br>
**Rule Format:** Kusto Query Language (KQL)
</div>

!!! danger "Verdict: True Positive — High Severity — Account Compromised"
    Target host `FIN-WKSTN-04` registered 142 failed network authentication attempts (Event ID 4625, SubStatus `0xC000006A`) across a 12-minute window from source endpoint `192.168.10.45`, followed immediately by a successful logon (Event ID 4624) under domain account `CORP\jdoe`. Immediate containment executed.

---

## 1. Investigation Scope & Objectives

Adversaries systematically deploy automated dictionary attacks and password spraying against network authentication interfaces to acquire valid enterprise credentials.

This investigation focused on:
1. Ingesting Windows Security event telemetry into an Azure Log Analytics Workspace via Azure Monitor Agent (AMA).
2. Analyzing diagnostic status codes within Event ID 4625 to differentiate account lockouts from invalid credentials.
3. Constructing an analytics rule in KQL that correlates anomalous bursts of failed logons followed by a successful logon event within a short timeframe.

---

## 2. Windows Authentication Telemetry

| Event ID | Description | Critical Correlation Fields |
|---|---|---|
| **4625** | An account failed to log on | `TargetUserName`, `LogonType`, `SubStatus`, `IpAddress`, `WorkstationName` |
| **4624** | An account successfully logged on | `TargetUserName`, `LogonType`, `TargetLogonId`, `IpAddress`, `Computer` |

### Diagnostic Failure Sub-Status Codes

* `0xC000006A`: `STATUS_WRONG_PASSWORD` (Username exists; credential guess was incorrect).
* `0xC000006D`: `STATUS_LOGON_FAILURE` (General failure or invalid username).
* `0xC0000072`: `STATUS_ACCOUNT_DISABLED` (Account is administratively disabled).
* `0xC0000234`: `STATUS_ACCOUNT_LOCKED_OUT` (Consecutive failures exceeded threshold).

---

## 3. Incident Timeline

| Timestamp (UTC) | Event ID | User | Source IP | Logon Type | Diagnostic Code | Finding |
|---|---|---|---|---|---|---|
| `14:02:11` - `14:14:05` | 4625 (x142) | `CORP\jdoe` | `192.168.10.45` | 3 (Network) | `0xC000006A` | High-frequency password guessing. |
| `14:14:28` | **4624** | `CORP\jdoe` | `192.168.10.45` | 3 (Network) | N/A | **Successful authentication.** |
| `14:15:10` | 4688 | `CORP\jdoe` | Local Host | N/A | N/A | Discovery: `whoami /all` executed. |

---

## 4. Detection Engineering: Microsoft Sentinel Analytics Rule (KQL)

```kql
let timeRange = 1h;
let failureThreshold = 10;
let failedLogons = SecurityEvent
    | where TimeGenerated >= ago(timeRange)
    | where EventID == 4625
    | where SubStatus == "0xc000006a"
    | where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "127.0.0.1"
    | summarize 
        FailureCount = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by TargetAccount, IpAddress, Computer;
let successfulLogons = SecurityEvent
    | where TimeGenerated >= ago(timeRange)
    | where EventID == 4624
    | where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "127.0.0.1"
    | project 
        SuccessTime = TimeGenerated,
        TargetAccount,
        IpAddress,
        Computer,
        LogonType;
failedLogons
| where FailureCount >= failureThreshold
| join kind=inner (successfulLogons) on TargetAccount, IpAddress, Computer
| where SuccessTime between (LastFailure .. (LastFailure + 10m))
| project 
    FirstFailure,
    LastFailure,
    SuccessTime,
    TargetAccount,
    Computer,
    SourceIpAddress = IpAddress,
    FailureCount,
    LogonType
| order by SuccessTime desc