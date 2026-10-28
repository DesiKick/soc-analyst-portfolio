---
title: ATT&CK Coverage Map
---

# MITRE ATT&CK Coverage Map

Which techniques my labs cover, how strong the coverage is, and where the gaps are.

| Coverage level | Meaning |
| :--- | :--- |
| <span class="pill done">Validated</span> | Detection tested against real attack telemetry |
| <span class="pill wip">Logic</span> | Detection written but not yet tested on real attack data |
| **Observed** | Seen and documented in an investigation, no detection yet |

---

## Covered Techniques

| Tactic | Technique | Lab | Coverage |
| :--- | :--- | :--- | :--- |
| Initial Access | [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) | [04](../investigations/lab-04-phishing-analysis.md) | **Observed** |
| Initial Access | [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | [04](../investigations/lab-04-phishing-analysis.md) | **Observed** |
| Execution | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | [01](../investigations/lab-01-windows-process.md) | <span class="pill wip">Logic</span> |
| Execution | [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) | [01](../investigations/lab-01-windows-process.md), [04](../investigations/lab-04-phishing-analysis.md) | <span class="pill wip">Logic</span> |
| Persistence / Privilege Escalation | [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/) | [03](../investigations/lab-03-splunk-lsass.md) | **Observed** |
| Defense Evasion | [T1036 Masquerading](https://attack.mitre.org/techniques/T1036/) (renamed ProcDump) | [03](../investigations/lab-03-splunk-lsass.md) | <span class="pill done">Validated</span> |
| Defense Evasion | [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011/) (`comsvcs.dll MiniDump`) | [03](../investigations/lab-03-splunk-lsass.md) | <span class="pill done">Validated</span> |
| Defense Evasion | [T1218.009 Regsvcs/Regasm](https://attack.mitre.org/techniques/T1218/009/) | [04](../investigations/lab-04-phishing-analysis.md) | <span class="pill wip">Logic</span> |
| Defense Evasion | [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004/) (dump cleanup) | [03](../investigations/lab-03-splunk-lsass.md) | **Observed** |
| Credential Access | [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | [03](../investigations/lab-03-splunk-lsass.md) | <span class="pill done">Validated</span> |
| Credential Access | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | [05](../investigations/lab-05-sentinel-bruteforce.md), [07](../investigations/lab-07-ad-bruteforce.md) | <span class="pill done">Validated</span> (real AD domain) |
| Credential Access | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | [05](../investigations/lab-05-sentinel-bruteforce.md), [07](../investigations/lab-07-ad-bruteforce.md) | <span class="pill done">Validated</span> (real AD domain) |
| Discovery | [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/) | [05](../investigations/lab-05-sentinel-bruteforce.md) | **Observed** (scenario) |
| Command and Control | [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | [02](../investigations/lab-02-network-traffic.md) | <span class="pill wip">Logic</span> |

T1036 and T1218.011 count as validated because the Lab 03 LSASS rule caught the renamed ProcDump and the `rundll32` dump in real telemetry. The rule targets LSASS access, so it catches those techniques only when they are used against LSASS.

---

## Known Gaps

The tactics I have not covered yet, and how I plan to close them:

| Tactic | Example techniques | Plan |
| :--- | :--- | :--- |
| Persistence | T1053.005 Scheduled Task, T1547.001 Registry Run Keys | Home lab: create both, detect with 4698 and Sysmon 13 |
| Lateral Movement | T1021.001 RDP, T1021.002 SMB/Admin Shares, T1550.002 Pass the Hash | Home lab AD build, detect with 4624 logon types 3/10 and 4648 |
| Credential Access (Kerberos) | T1558.003 Kerberoasting | Home lab: detect RC4 service ticket requests in 4769 |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Lab 07 network work |
| Cloud and Identity | Entra ID sign-in abuse | Sentinel workspace sign-in logs |
