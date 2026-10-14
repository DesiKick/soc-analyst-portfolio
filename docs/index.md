---
title: Home
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Mian Talha Nayyar

<p class="tagline">SOC Analyst | Incident Response | Detection Engineering</p>

I investigate alerts the way a SOC runs them: pull the telemetry, rebuild what happened, make a call, and turn the finding into a detection. 4+ years in security operations across financial services and managed IT. SC-200 certified.

[:material-folder-search: View Investigations](investigations/index.md){ .md-button .md-button--primary }
[:material-file-account: Resume](assets/files/Mian_Nayyar_SOC_Analyst_Resume.pdf){ .md-button }
[:fontawesome-brands-linkedin: LinkedIn](https://www.linkedin.com/in/mian-nayyar){ .md-button }
[:material-email: Email Me](mailto:talha397@gmail.com){ .md-button }

</div>

<div class="stats">
  <div><strong>4</strong><span>Investigations</span></div>
  <div><strong>163</strong><span>LSASS events triaged</span></div>
  <div><strong>0 / 108</strong><span>Benign events alerted</span></div>
  <div><strong>SC-200</strong><span>Microsoft certified</span></div>
</div>

---

## Featured Investigations

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Lab 03: LSASS Credential Dumping**

    ---

    Hunted 851 Sysmon events in Splunk, rebuilt a 6-method credential dumping attack, and shipped a detection that flagged every tool that read LSASS without alerting on a single benign system process.

    `Splunk` `SPL` `Sysmon` `T1003.001`

    [:octicons-arrow-right-24: Read the investigation](investigations/lab-03-splunk-lsass.md)

-   :material-email-alert:{ .lg .middle } **Lab 04: Phishing Email Analysis**

    ---

    Triaged spoofed PayPal, Netflix, Apple, and DHL lures. Traced redirect chains, tracking pixels, and weaponized attachments to a defanged IOC set.

    `Header Forensics` `CyberChef` `T1566`

    [:octicons-arrow-right-24: Read the investigation](investigations/lab-04-phishing-analysis.md)

-   :material-lan:{ .lg .middle } **Lab 02: Network Traffic Analysis**

    ---

    Reconstructed a cleartext HTTP session over IPv6, fingerprinted a non-standard client, and documented what to carve and hash in a live case.

    `Wireshark` `PCAP` `T1071.001`

    [:octicons-arrow-right-24: Read the investigation](investigations/lab-02-network-traffic.md)

-   :material-microsoft-windows:{ .lg .middle } **Lab 01: Windows Process Auditing**

    ---

    Enabled process creation auditing, analyzed Event ID 4688 lineage, and wrote a parent-child detection for Office macro abuse.

    `Event Viewer` `4688` `T1059`

    [:octicons-arrow-right-24: Read the investigation](investigations/lab-01-windows-process.md)

</div>

---

## How Each Lab Is Built

Every investigation follows the same structure a SOC ticket would:

1. **Alert or objective.** What fired, or what I set out to find.
2. **Evidence.** Raw logs, packets, or headers, with the queries used to pull them.
3. **Timeline and findings.** What happened, in order, backed by artifacts.
4. **Verdict.** True positive or false positive, severity, and escalation call.
5. **Detection.** A rule that catches it next time, tested against the same data.

Raw evidence and detection rules live in the [GitHub repo](https://github.com/DesiKick/soc-analyst-portfolio) so every result can be reproduced.

---

## Tools Used in These Labs

| Area | Tools |
|---|---|
| SIEM and Logs | Splunk (SPL), Sysmon, Windows Security Event Log |
| Network | Wireshark |
| Email and Triage | Header analysis, CyberChef, URL defanging |
| Frameworks | MITRE ATT&CK, Sigma |

Professional stack (Voya Financial, RTCS): Splunk, CrowdStrike Falcon, Splunk SOAR, Python. See [About](about.md).

---

## In Progress

<span class="pill wip">Building</span> **Lab 05: Brute Force Detection in Microsoft Sentinel (KQL).** Event ID 4625 spikes followed by a 4624 success.

<span class="pill wip">Building</span> **Lab 06: Python IOC Enrichment.** Script that enriches IPs and domains through the VirusTotal API.

<span class="pill wip">Building</span> **Lab 07: C2 Beacon Hunting.** Spotting periodic callbacks in a PCAP.