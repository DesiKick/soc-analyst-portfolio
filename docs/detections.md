---
title: Detections
---

# Detection Library

Rules built during the investigations, each tested against the lab data it came from. Source files are in the repository's `detections/` directory.

| Rule | Platform | ATT&CK | Validation | Origin |
|---|---|---|---|---|
| Suspicious LSASS Memory Access | Splunk SPL, Sigma | T1003.001 | 163 LSASS events: 55 alerts, 0 of 108 benign events alerted | [Lab 03](investigations/lab-03-splunk-lsass.md) |
| Office Binary Spawning Shell | Splunk SPL | T1059, T1204.002 | Process lineage logic against macro exploitation | [Lab 01](investigations/lab-01-windows-process.md) |
| Workstation Cleartext Outbound HTTP | Wireshark / Splunk SPL | T1071.001 | Non-standard User-Agent filtering | [Lab 02](investigations/lab-02-network-traffic.md) |

---

## Suspicious LSASS Memory Access (Splunk SPL)

```spl
index=botsv1 "<EventID>10</EventID>"
| rex field=_raw "<Data Name="SourceImage">(?<SourceImage>[^<]+)</Data>"
| rex field=_raw "<Data Name="TargetImage">(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name="GrantedAccess">(?<GrantedAccess>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<host_name>[^<]+)</Computer>"
| where match(TargetImage, "(?i)\\\\lsass\.exe$")
| where match(GrantedAccess, "(?i)^0x(1fffff|1010|1410|1438|143a|1f3fff)$")
| where NOT match(SourceImage, "(?i)^C:\\\\Windows\\\\System32\\\\(svchost|wininit|csrss|services|lsm)\.exe$")
| eval severity=if(match(SourceImage, "(?i)\\\\(AppData|Temp|Users\\\\Public)\\\\"), "critical", "high")
| stats count min(_time) as first_seen max(_time) as last_seen values(GrantedAccess) as access by host_name SourceImage severity
| sort - count

```yaml
title: Suspicious Process Access to LSASS Memory
status: experimental
author: Mian Talha Nayyar
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1fffff'
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1f3fff'
  filter_system:
    SourceImage:
      - 'C:\Windows\System32\svchost.exe'
      - 'C:\Windows\System32\wininit.exe'
      - 'C:\Windows\System32\csrss.exe'
      - 'C:\Windows\System32\services.exe'
      - 'C:\Windows\System32\lsm.exe'
  condition: selection and not filter_system
falsepositives:
  - EDR and antivirus agents (add their paths after baselining)
  - Administrators creating a dump from Task Manager
level: high
```