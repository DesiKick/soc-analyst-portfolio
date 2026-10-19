---
title: SOC Analyst Portfolio & Detection Engineering
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Mian Talha Nayyar

<p class="tagline">Incident Response Engineer &bull; SOC Specialist &bull; Detection Engineer</p>

<p class="lead">
Enterprise incident response, forensic telemetry analysis, and threat detection engineering. Every lab reconstructs real-world adversary behavior from raw packet captures, memory access, and process telemetry into validated Splunk SPL, Sigma, and KQL detection rules.
</p>

[:material-file-account: Resume (PDF)](assets/files/Mian_Nayyar_SOC_Analyst_Resume.pdf){ .md-button .md-button--primary }
[:material-file-document: Cover Letter (PDF)](assets/files/Mian_Nayyar_Cover_Letter.pdf){ .md-button }
[:material-folder-search: Browse Investigations](investigations/index.md){ .md-button }
[:fontawesome-brands-linkedin: LinkedIn Profile](https://www.linkedin.com/in/mian-nayyar){ .md-button }
[:material-email: Contact Analyst](mailto:talha397@gmail.com){ .md-button }

</div>

<div class="stats">
  <div><strong>4+</strong><span>Active Case Studies</span></div>
  <div><strong>163</strong><span>LSASS Events Triaged</span></div>
  <div><strong>0 / 108</strong><span>False Positive Rate</span></div>
  <div><strong>SC-200</strong><span>Microsoft Certified</span></div>
</div>

---

## 🎯 Featured SOC Investigations

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Lab 03: LSASS Credential Dumping (Splunk)**

    ---

    Hunted 851 endpoint Sysmon events in Splunk SIEM, dissected a multi-stage adversary memory dump, and engineered a behavioral detection rule excluding benign OS processes with zero false positives.

    `Splunk` `Sysmon Event ID 10` `T1003.001` `SPL`

    [:octicons-arrow-right-24: Read Incident Report](investigations/lab-03-splunk-lsass.md)

-   :material-email-alert:{ .lg .middle } **Lab 04: Inbound Phishing & Header Forensics**

    ---

    Triaged weaponized email lures mimicking financial institutions and delivery vendors. Deconstructed raw RFC 822 headers, tracked multi-hop redirect chains, and isolated tracking web beacons.

    `RFC 822 Headers` `CyberChef` `T1566` `Defanging`

    [:octicons-arrow-right-24: Read Incident Report](investigations/lab-04-phishing-analysis.md)

-   :material-lan:{ .lg .middle } **Lab 02: Network Traffic & C2 Stream Reconstruction**

    ---

    Triaged packet capture (PCAP) streams in Wireshark over IPv6. Filtered application-layer HTTP requests, fingerprinted terminal User-Agents, and carved unencrypted payload streams.

    `Wireshark` `PCAP` `TCP Stream Carving` `T1071.001`

    [:octicons-arrow-right-24: Read Incident Report](investigations/lab-02-network-traffic.md)

-   :material-microsoft-windows:{ .lg .middle } **Lab 01: Windows Process Auditing & Execution**

    ---

    Configured advanced Windows security audit policies for Event ID 4688. Analyzed parent-child process relationships to detect Living-off-the-Land abuse and malicious macro execution.

    `Event Viewer` `Event ID 4688` `Process Trees` `T1059`

    [:octicons-arrow-right-24: Read Incident Report](investigations/lab-01-windows-process.md)

</div>

---

## 🛡️ Defensive Engineering Standards

Every investigation in this repository follows formal SOC triage standards:

1. **Initial Trigger & Scope:** Documenting alert provenance, affected host, and user context.
2. **Forensic Telemetry:** Direct examination of raw `.evtx`, PCAPs, or mail headers.
3. **Timeline & Pivoting:** Reconstructing chronological attacker execution steps.
4. **Actionable Detection:** Validated detection queries (SPL, Sigma, KQL) tested directly against attack datasets.

---

## 🚀 Active Roadmap

| Target Module | Investigation Focus | Tooling / Telemetry | Status |
| :--- | :--- | :--- | :--- |
| **Lab 05** | Windows Authentication & Brute Force Analysis | Event ID 4625 / 4624, Microsoft Sentinel (KQL) | <span class="pill done">Complete</span> |
| **Lab 06** | Automated Threat Intelligence IOC Enrichment | Python 3, VirusTotal API, AbuseIPDB | <span class="pill wip">Planned</span> |
| **Lab 07** | Periodic Command & Control (C2) Beacon Hunting | RITA, Zeek Logs, Network Jitter Analysis | <span class="pill wip">Planned</span> |