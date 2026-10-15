---
title: Detections
---

# Detection Engineering Library

Detection rules built during the investigations and mapped to MITRE ATT&CK. Source files are in the repo's [`detections/`](https://github.com/DesiKick/soc-analyst-portfolio/tree/main/detections) folder.

| Rule | Detection Platform | MITRE ATT&CK | Validation Dataset | Source Investigation |
| :--- | :--- | :--- | :--- | :--- |
| **Suspicious LSASS Memory Access** | Splunk SPL, Sigma | T1003.001 | 163 LSASS access events (55 alerts: 54 confirmed, 1 needs context; 0 of 108 benign events alerted) | [Lab 03: Splunk SIEM](investigations/lab-03-splunk-lsass.md) |
| **Office Binary Spawning Shell** | Splunk SPL | T1059, T1204.002 | Logic only, not yet tested on attack data | [Lab 01: Process Auditing](investigations/lab-01-windows-process.md) |
| **Outbound Cleartext HTTP Workstation** | Splunk SPL, Wireshark | T1071.001 | Logic only, not yet tested on attack data | [Lab 02: Network Traffic](investigations/lab-02-network-traffic.md) |

---

## Suspicious LSASS Memory Access (Splunk SPL)

Filters on Sysmon Event ID 10 where the target is `lsass.exe` and the access mask includes memory read permissions (`0x1fffff`, `0x1010`, `0x1410`), excluding core system processes.

```spl
index=botsv1 "<EventID>10</EventID>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='GrantedAccess'>(?<GrantedAccess>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<host_name>[^<]+)</Computer>"
| where match(TargetImage, "(?i)\\\\lsass\.exe$")
| where match(GrantedAccess, "(?i)^0x(1fffff|1010|1410|1438|143a|1f3fff)$")
| where NOT match(SourceImage, "(?i)^C:\\\\Windows\\\\System32\\\\(svchost|wininit|csrss|services|lsm)\.exe$")
| eval severity=if(match(SourceImage, "(?i)\\\\(AppData|Temp|Users\\\\Public)\\\\"), "critical", "high")
| stats count min(_time) as first_seen max(_time) as last_seen values(GrantedAccess) as access by host_name SourceImage severity
| sort - count
```

??? example "View Sigma Rule Definition"

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
      - EDR and antivirus monitoring agents
      - Legitimate administrator memory dumps via Task Manager
    level: high
    ```

---

## Office Application Spawning Command Shell (Splunk SPL)

Detects living-off-the-land techniques where Microsoft Office applications spawn command interpreters (`cmd.exe`, `powershell.exe`) indicative of macro exploitation.

```spl
index=wineventlog EventCode=4688
| eval parent=lower(Creator_Process_Name), child=lower(New_Process_Name)
| where match(parent, "\\\\(winword|excel|powerpnt|outlook|onenote)\.exe$")
    AND match(child, "\\\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")
| table _time host Account_Name parent child Process_Command_Line
```

---

## Outbound Cleartext HTTP from Internal Workstation (Splunk SPL)

Isolates direct outbound cleartext HTTP (port 80) connections originating from endpoints using non-standard or scripted user agents.

```spl
index=proxy dest_port=80
| where NOT match(http_user_agent, "(?i)(mozilla|windows-update|microsoft)")
| stats count values(url) as urls dc(dest) as destinations by src http_user_agent
| where count > 5
```
