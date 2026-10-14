# Security Operations & Threat Hunting Investigations

| Investigation | Focus Area / Techniques | Telemetry & Tooling | MITRE ATT&CK Mapping | Status |
| :--- | :--- | :--- | :--- | :--- |
| **[Lab 01: Windows Process Auditing](lab-01-windows-process.md)** | Process creation, parent-child tracking, CLI analysis | Windows Event ID 4688, CLI Logging | T1059 (Command & Scripting Interpreter) | **Complete** |
| **[Lab 02: Network Traffic Analysis](lab-02-network-traffic.md)** | PCAP packet analysis, C2 payload extraction, hash triage | Wireshark, TCP Stream Carving, SHA-256 | T1071 (Application Layer Protocol) | **Complete** |
| **[Lab 03: Splunk SIEM Detection](lab-03-splunk-lsass.md)** | LSASS memory dump detection, regex field extraction | Splunk SIEM, Sysmon Event ID 10, SPL | T1003.001 (LSASS Memory) | **Complete** |
| **[Lab 04: Inbound Phishing Analysis](lab-04-phishing-analysis.md)** | Header forensics, URL defanging, macro document triage | RFC 822 Headers, Web Beacons, Defanging | T1566 (Phishing) | **Complete** |