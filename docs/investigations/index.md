# Investigations

Each lab documents one case from raw telemetry to a verdict and a detection. New here? Start with the [Foundations](../foundations/lab-environment.md) pages. Raw evidence is in the repo's [`evidence/`](https://github.com/DesiKick/soc-analyst-portfolio/tree/main/evidence) folder.


| Investigation | Focus Area / Techniques | Telemetry & Tooling | MITRE ATT&CK Mapping | Status |
| :--- | :--- | :--- | :--- | :--- |
| **[Lab 01: Windows Process Auditing](lab-01-windows-process.md)** | Process creation, parent-child lineage, command line logging | Windows Event ID 4688, CLI Logging | T1059 (Command & Scripting Interpreter) | <span class="pill done">Complete</span> |
| **[Lab 02: Network Traffic Analysis](lab-02-network-traffic.md)** | PCAP triage, HTTP stream reconstruction, client fingerprinting | Wireshark, Follow TCP Stream | T1071 (Application Layer Protocol) | <span class="pill done">Complete</span> |
| **[Lab 03: LSASS Credential Dumping](lab-03-splunk-lsass.md)** | Threat hunt, attack timeline, validated detection | Splunk SIEM, Sysmon Event ID 10, SPL | T1003.001 (LSASS Memory) | <span class="pill done">Complete</span> |
| **[Lab 04: Inbound Phishing Analysis](lab-04-phishing-analysis.md)** | Header forensics, redirect chains, attachment triage | Header analysis, CyberChef, defanging | T1566 (Phishing) | <span class="pill done">Complete</span> |
| **[Lab 05: Brute Force Detection Logic](lab-05-sentinel-bruteforce.md)** | Failure-then-success correlation, password spraying | KQL, Azure Data Explorer, Event ID 4625 / 4624 | T1110.001, T1110.003 | <span class="pill done">Complete</span> (simulated data) |
| **Lab 05 v2: Brute Force on Real Telemetry** | Rerun Lab 05 rules on live logs | Windows VM, Microsoft Sentinel | T1110 | <span class="pill wip">Planned</span> |
| **Lab 06: IOC Enrichment Script** | Automated IP and domain enrichment, code in repo | Python, VirusTotal API, AbuseIPDB | N/A | <span class="pill wip">Planned</span> |
| **Lab 07: C2 Beacon Hunting** | Periodic callback detection | Zeek, RITA | T1071 | <span class="pill wip">Planned</span> |

!!! tip "Start here"
    [Lab 03](lab-03-splunk-lsass.md) is the most complete case: a full attack timeline, a verdict, and a detection tested against the same data.
