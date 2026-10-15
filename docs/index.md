---
title: SOC Analyst Portfolio & Detection Engineering
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Mian Talha Nayyar

<p class="tagline">SOC Analyst &bull; Incident Response &bull; Detection Engineering</p>

<p class="lead">
Hands-on lab investigations built from raw telemetry. Each one goes from logs, packets, or headers to a verdict and a detection. 4+ years in security operations across financial services and managed IT.
</p>

[:material-folder-search: Browse Investigations](investigations/index.md){ .md-button .md-button--primary }
[:material-file-account: Resume (PDF)](assets/files/Mian_Nayyar_SOC_Analyst_Resume.pdf){ .md-button }
[:fontawesome-brands-linkedin: LinkedIn Profile](https://www.linkedin.com/in/mian-nayyar){ .md-button }
[:material-email: Email Me](mailto:talha397@gmail.com){ .md-button }

</div>

<div class="stats">
  <div><strong>4</strong><span>Lab Investigations</span></div>
  <div><strong>163</strong><span>LSASS Access Events Triaged</span></div>
  <div><strong>0 / 108</strong><span>Benign Events Alerted</span></div>
  <div><strong>SC-200</strong><span>Microsoft Certified</span></div>
</div>

---

## 🎯 Featured SOC Investigations

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Lab 03: LSASS Credential Dumping (Splunk)**

    ---

    Hunted 851 endpoint Sysmon events in Splunk SIEM, rebuilt a 6-method credential dumping attack, and wrote a behavior-based detection that flagged every dumping tool without alerting on a single benign system process.

    `Splunk` `Sysmon Event ID 10` `T1003.001` `SPL`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-03-splunk-lsass.md)

-   :material-email-alert:{ .lg .middle } **Lab 04: Inbound Phishing & Header Forensics**

    ---

    Triaged weaponized email lures mimicking financial institutions and delivery vendors. Deconstructed raw RFC 822 headers, tracked multi-hop redirect chains, and isolated tracking web beacons.

    `RFC 822 Headers` `CyberChef` `T1566` `Defanging`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-04-phishing-analysis.md)

-   :material-lan:{ .lg .middle } **Lab 02: Network Traffic & HTTP Stream Reconstruction**

    ---

    Triaged packet capture (PCAP) streams in Wireshark over IPv6. Filtered application-layer HTTP requests, reconstructed the full TCP session, and fingerprinted a non-browser client.

    `Wireshark` `PCAP` `Follow TCP Stream` `T1071.001`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-02-network-traffic.md)

-   :material-microsoft-windows:{ .lg .middle } **Lab 01: Windows Process Auditing & Execution**

    ---

    Configured advanced Windows security audit policies for Event ID 4688. Analyzed parent-child process relationships to detect Living-off-the-Land abuse and malicious macro execution.

    `Event Viewer` `Event ID 4688` `Process Trees` `T1059`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-01-windows-process.md)

</div>

---

## 🛡️ Defensive Engineering Standards

Every investigation follows the same structure as a SOC ticket:

1. **Initial Trigger & Scope:** Documenting the alert provenance, affected host, and user context.
2. **Forensic Telemetry:** Raw Sysmon logs, PCAPs, or mail headers, with the queries used to pull them. Raw files live in the repo's `evidence/` folder.
3. **Timeline & Pivoting:** Reconstructing chronological attacker execution steps.
4. **Verdict:** True or false positive, severity, and escalation call.
5. **Detection:** A rule that catches it next time, tested against the lab data where possible.

---

## 🚀 Active Roadmap

| Target Module | Investigation Focus | Tooling / Telemetry | Status |
| :--- | :--- | :--- | :--- |
| **Lab 05** | Windows Authentication & Brute Force Analysis | Event ID 4625 / 4624, Microsoft Sentinel (KQL) | <span class="pill wip">Building</span> |
| **Lab 06** | Automated Threat Intelligence IOC Enrichment | Python 3, VirusTotal API, AbuseIPDB | <span class="pill wip">Building</span> |
| **Lab 07** | Periodic Command & Control (C2) Beacon Hunting | RITA, Zeek Logs, Network Jitter Analysis | <span class="pill wip">Building</span> |