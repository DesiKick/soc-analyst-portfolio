---
title: 'Lab 05: Microsoft Sentinel Brute Force Detection (KQL)'
---

# Lab 05: Windows Authentication & Brute Force Detection in Microsoft Sentinel (KQL)

<div class=\"lab-meta\" markdown>
**Category:** Cloud SIEM & Identity Detection Engineering<br>
**MITRE ATT&CK:** [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) &bull; [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) &bull; [T1059.003 Command & Scripting Interpreter](https://attack.mitre.org/techniques/T1059/003/)<br>
**Platform:** Microsoft Sentinel / Azure Log Analytics Workspace<br>
**Telemetry Agent:** Azure Monitor Agent (AMA) / Windows Security Event Log<br>
**Rule Format:** Kusto Query Language (KQL) Analytic Rule
</div>

!!! danger \"Incident Verdict: True Positive — High Severity — Identity Compromised\"
    Target workstation \`FIN-WKSTN-04\` sustained **142 consecutive network authentication failures** (Event ID 4625, SubStatus \`0xC000006A\`) within a 12-minute window originating from internal IP \`192.168.10.45\`. The attack culminated in a successful logon (Event ID 4624) under domain account \`CORP\\\\jdoe\`, followed immediately by suspicious discovery command execution (\`whoami /all\`). Immediate host containment, session termination, and credential revocation were executed.

---

## 1. Executive Summary & Forensic Artifacts

During continuous security monitoring in Microsoft Sentinel, analytics detected an anomalous spike in SMB network authentications targeting a high-value finance workstation. Investigation confirmed an adversary executed an automated dictionary brute-force attack against local Active Directory credentials.

### Forensic Telemetry Breakdown

| Observable Property | Forensic Artifact Value | Operational Significance |
| :--- | :--- | :--- |
| **Target Hostname** | \`FIN-WKSTN-04.corp.local\` | Finance Department Workstation (Tier-2 Asset) |
| **Compromised Identity** | \`CORP\\\\jdoe\` | Domain User Account |
| **Adversary Source IP** | \`192.168.10.45\` | Ephemeral Workstation on Subnet \`192.168.10.0/24\` |
| **Authentication Protocol** | \`NTLMSSP\` (Logon Type 3 – Network) | SMB session negotiation over TCP port 445 |
| **Failure Volume** | 142 Events (\`SubStatus: 0xC000006A\`) | Dictionary attack using valid username and password list |
| **Compromise Timestamp** | \`2026-10-14 14:14:28 UTC\` | Successful authentication (Event ID 4624) |
| **Post-Exploit Spawn** | \`whoami /all\` (PID 4912) | Security context and group membership reconnaissance |

---

## 2. Windows Authentication Mechanics & Telemetry Deep-Dive

Windows audit logging generates distinct Event IDs for authentication attempts. Differentiating benign user error from brute force requires parsing the raw XML event data.

### Relevant Windows Event IDs

* **Event ID 4625 (An account failed to log on):** Generated on the system where the logon attempt occurred. Provides source IP, target account, and the exact NTSTATUS failure code.
* **Event ID 4624 (An account successfully logged on):** Generated upon successful authentication. Critical for identifying whether an adversary guessed the password.
* **Event ID 4688 (A new process has been created):** Captures post-compromise activity if command-line process auditing is active.

### Diagnostic NTSTATUS Hex Codes (Event ID 4625)

The \`SubStatus\` field is the primary indicator of adversary intent:

| SubStatus Code | NTSTATUS Macro | Root Cause Analysis | Analyst Interpretation |
| :--- | :--- | :--- | :--- |
| \`0xC000006A\` | \`STATUS_WRONG_PASSWORD\` | Account exists; password incorrect. | **Primary indicator of brute force / password guessing.** |
| \`0xC000006D\` | \`STATUS_LOGON_FAILURE\` | General authentication error. | Typically accompanies bad credentials or mismatched domains. |
| \`0xC0000064\` | \`STATUS_NO_SUCH_USER\` | The specified user does not exist. | Indicator of user enumeration or spraying unverified lists. |
| \`0xC0000072\` | \`STATUS_ACCOUNT_DISABLED\` | Account is administratively disabled. | Adversary attempting to access dormant accounts. |
| \`0xC0000234\` | \`STATUS_ACCOUNT_LOCKED_OUT\` | Account locked out due to policy. | Brute force triggered Active Directory account lockout. |

<figure markdown>
  ![Windows Event ID 4625 Audit Telemetry](../assets/images/lab05-event-4625-failure.png)
  <figcaption>Figure 5.1: Windows Security Audit log exhibiting Event ID 4625 with SubStatus 0xC000006A (STATUS_WRONG_PASSWORD) targeting user jdoe over Logon Type 3 (Network SMB).</figcaption>
</figure>

---

## 3. Incident Timeline & Attack Reconstruction

By correlating event sequences across Azure Log Analytics, the attack was reconstructed chronologically:

| Timestamp (UTC) | Event ID | Account | Source IP | Logon Type | Diagnostic Field | Analyst Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| \`14:02:11\` | 4625 | \`CORP\\\\jdoe\` | \`192.168.10.45\` | 3 (Network) | \`0xC000006A\` | Attack initialization: automated script begins password attempts. |
| \`14:08:34\` | 4625 | \`CORP\\\\jdoe\` | \`192.168.10.45\` | 3 (Network) | \`0xC000006A\` | 75th failure reached; high frequency confirms automated tool. |
| \`14:14:05\` | 4625 | \`CORP\\\\jdoe\` | \`192.168.10.45\` | 3 (Network) | \`0xC000006A\` | Final failure recorded (142 total failures). |
| \`14:14:28\` | **4624** | \`CORP\\\\jdoe\` | \`192.168.10.45\` | 3 (Network) | \`TargetLogonId: 0x3E7\` | **Successful logon.** Credential guessed. |
| \`14:15:10\` | 4688 | \`CORP\\\\jdoe\` | \`FIN-WKSTN-04\` | Local | \`whoami /all\` | Adversary establishes CLI session and checks privilege tokens. |

---

## 4. Detection Engineering: Microsoft Sentinel KQL Analytic Rule

Alerting on Event ID 4625 alone produces unacceptable false positive rates from mistyped passwords. This production KQL rule correlates 10+ failed logons with a successful authentication matching the same identity, source IP, and computer within 10 minutes:

\`\`\`kql
let timeRange = 1h;
let failureThreshold = 10;
let successWindow = 10m;
let failedLogons = SecurityEvent
    | where TimeGenerated >= ago(timeRange)
    | where EventID == 4625
    | where SubStatus == \"0xc000006a\"
    | where isnotempty(IpAddress) and IpAddress !in (\"-\", \"127.0.0.1\", \"::1\")
    | summarize 
        FailureCount = count(),
        FirstFailure = min(TimeGenerated),
        LastFailure = max(TimeGenerated)
        by TargetAccount, IpAddress, Computer;
let successfulLogons = SecurityEvent
    | where TimeGenerated >= ago(timeRange)
    | where EventID == 4624
    | where isnotempty(IpAddress) and IpAddress !in (\"-\", \"127.0.0.1\", \"::1\")
    | project 
        SuccessTime = TimeGenerated,
        TargetAccount,
        IpAddress,
        Computer,
        LogonType;
failedLogons
| where FailureCount >= failureThreshold
| join kind=inner (successfulLogons) on TargetAccount, IpAddress, Computer
| where SuccessTime between (LastFailure .. (LastFailure + successWindow))
| extend TimeDeltaSeconds = datetime_diff('second', SuccessTime, LastFailure)
| project 
    FirstFailure,
    LastFailure,
    SuccessTime,
    TimeDeltaSeconds,
    TargetAccount,
    VictimHost = Computer,
    AttackerIP = IpAddress,
    FailureCount,
    LogonType
| order by SuccessTime desc
\`\`\`

<figure markdown>
  ![Microsoft Sentinel KQL Analytics Rule Execution](../assets/images/lab05-sentinel-kql-query.png)
  <figcaption>Figure 5.2: Microsoft Sentinel execution displaying the correlated True Positive incident: 142 failed password attempts followed by successful compromise within 23 seconds.</figcaption>
</figure>

---

## 5. Containment & Incident Response Playbook

Once the analytic rule triggered, the following response procedure was initiated:

1. **Immediate Host Isolation:** Workstation \`FIN-WKSTN-04\` was isolated from the network via Defender for Endpoint to prevent lateral movement.
2. **Identity Revocation:** Terminated active Kerberos Ticket-Granting Tokens (TGT) and initiated a forced password reset on domain user \`CORP\\\\jdoe\`.
3. **Source Quarantine:** Network port for attacker host \`192.168.10.45\` was shut down on the core switch pending physical forensics.
4. **Domain-Wide Audit:** Executed fleet-wide KQL queries across all domain controllers for subsequent \`EventID == 4624\` occurrences originating from \`192.168.10.45\`.
'''

with open('docs/investigations/lab-05-sentinel-bruteforce.md', 'w', encoding='utf-8') as f:
    f.write(content.strip() + '\n')
print('Successfully wrote formatted Markdown with proper code fence newlines!')
"