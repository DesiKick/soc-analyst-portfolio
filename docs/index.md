---
title: SOC Analyst Portfolio
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# Mian Talha Nayyar

<p class="tagline">SOC Analyst &bull; Incident Response &bull; Detection Engineering</p>

<p class="lead">
Hands-on lab investigations built from raw telemetry. Each one goes from logs, packets, or headers to a verdict and a detection, with the evidence in the repo so you can check my work. 4+ years in security operations across financial services and managed IT.
</p>

[:material-file-account: Resume (PDF)](assets/files/Mian_Nayyar_SOC_Analyst_Resume.pdf){ .md-button .md-button--primary }
[:material-folder-search: Browse Investigations](investigations/index.md){ .md-button }
[:fontawesome-brands-linkedin: LinkedIn](https://www.linkedin.com/in/mian-nayyar){ .md-button }
[:material-email: Email Me](mailto:talha397@gmail.com){ .md-button }

</div>

<div class="stats">
  <div><strong>5</strong><span>Lab Investigations</span></div>
  <div><strong>163</strong><span>LSASS Events Triaged</span></div>
  <div><strong>0 / 108</strong><span>Benign Events Alerted</span></div>
  <div><strong>SC-200</strong><span>Microsoft Certified</span></div>
</div>

---

## What I Do

I protect companies from cyberattacks. Security tools raise thousands of alerts: failed logins, suspicious programs, phishing emails. Most are harmless. **My job is to find the real attacks fast, stop them before they spread, and make the alarms smarter so the team wastes less time on noise.**

<div class="grid cards" markdown>

-   :material-bell-alert:{ .lg .middle } **Triage and investigate**

    ---

    Work the alert queue, decide what is real, and reconstruct exactly what happened. 45+ alerts and incidents a week at Voya Financial.

-   :material-tune-variant:{ .lg .middle } **Build and tune detections**

    ---

    Write the rules that raise alerts, and fix the ones that cry wolf. 100+ detections built and tuned, 35% fewer false alarms.

-   :material-robot-outline:{ .lg .middle } **Automate the routine**

    ---

    Python that does an analyst's repetitive lookups automatically. Investigations cut from 15 minutes to 15 seconds.

</div>

!!! tip "Not from a security background?"
    Start with [What a SOC Analyst Does](foundations/what-a-soc-does.md). Every lab also opens with an **In plain English** summary, and the [Glossary](foundations/glossary.md) explains every term.

---

## Start Here: How I Work

Before the labs, these pages explain the job, how I set up my environment, how I triage, and what I know cold.

<div class="grid cards" markdown>

-   :material-shield-account:{ .lg .middle } **What a SOC Analyst Does**

    ---

    The job in plain English: how an alert becomes a decision, the tools, my day to day, and where I'm growing.

    [:octicons-arrow-right-24: Start here](foundations/what-a-soc-does.md)

-   :material-server-network:{ .lg .middle } **Lab Environment**

    ---

    What each lab ran on, where the data came from, and how logs flow from source to SIEM.

    [:octicons-arrow-right-24: View setup](foundations/lab-environment.md)

-   :material-clipboard-check:{ .lg .middle } **How I Triage an Alert**

    ---

    My first five questions, verdict categories, severity matrix, escalation rules, and a sample ticket.

    [:octicons-arrow-right-24: Read the method](foundations/triage-method.md)

-   :material-format-list-numbered:{ .lg .middle } **Event ID Reference**

    ---

    The Windows and Sysmon events I rely on most, logon types, and the failure codes that matter.

    [:octicons-arrow-right-24: Open reference](foundations/event-reference.md)

-   :material-grid:{ .lg .middle } **ATT&CK Coverage Map**

    ---

    Which techniques my labs and detections cover, and where my gaps are.

    [:octicons-arrow-right-24: See coverage](foundations/attack-coverage.md)

-   :material-book-alphabet:{ .lg .middle } **Glossary**

    ---

    Every technical term on this site, explained in plain English.

    [:octicons-arrow-right-24: Open glossary](foundations/glossary.md)

</div>

---

## Featured Investigations

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Lab 03: LSASS Credential Dumping (Splunk)**

    ---

    Hunted 851 Sysmon events in Splunk, rebuilt a 6-method credential dumping attack, and wrote a behavior-based detection that flagged every dumping tool without alerting on a single benign system process.

    `Splunk` `Sysmon Event ID 10` `T1003.001` `SPL`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-03-splunk-lsass.md)

-   :material-email-alert:{ .lg .middle } **Lab 04: Phishing & Header Forensics**

    ---

    Triaged spoofed PayPal, Netflix, Apple, and DHL lures. Traced redirect chains, tracking pixels, and macro attachments to a defanged IOC set.

    `Header Analysis` `CyberChef` `T1566` `Defanging`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-04-phishing-analysis.md)

-   :material-account-lock:{ .lg .middle } **Lab 05: Brute Force Detection Logic (KQL)**

    ---

    Wrote KQL that correlates repeated 4625 failures with a 4624 success from the same source. Logic tested on simulated data, plus a real local test that exposed two gaps in the rule.

    `KQL` `Event ID 4625 / 4624` `T1110` `Azure Data Explorer`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-05-sentinel-bruteforce.md)

-   :material-lan:{ .lg .middle } **Lab 02: Network Traffic & HTTP Stream Reconstruction**

    ---

    Triaged a PCAP over IPv6 in Wireshark, isolated HTTP requests, reconstructed the full TCP session, and fingerprinted a non-browser client.

    `Wireshark` `PCAP` `Follow TCP Stream` `T1071.001`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-02-network-traffic.md)

-   :material-microsoft-windows:{ .lg .middle } **Lab 01: Windows Process Auditing**

    ---

    Enabled process creation auditing, analyzed Event ID 4688 parent-child lineage, and wrote detection logic for Office macro abuse.

    `Event Viewer` `Event ID 4688` `Process Trees` `T1059`

    [:octicons-arrow-right-24: Read Investigation](investigations/lab-01-windows-process.md)

</div>

---

## How Each Lab Is Built

Every investigation follows the same structure as a SOC ticket:

1. **Trigger and scope:** what fired or what I set out to find, the host, and the user.
2. **Evidence:** raw Sysmon logs, PCAPs, or mail headers, with the queries used to pull them. Raw files live in the repo's `evidence/` folder.
3. **Timeline and pivots:** what happened, in order, backed by artifacts.
4. **Verdict:** true or false positive, severity, and escalation call.
5. **Detection:** a rule that catches it next time, tested against real lab data where I had it, and labeled clearly where I did not.

---

## Roadmap

| Module | Focus | Tooling / Telemetry | Status |
| :--- | :--- | :--- | :--- |
| **Lab 01** | Windows Process Auditing & Execution | Event Viewer, Event ID 4688, Process Trees | <span class="pill done">Complete</span> |
| **Lab 02** | Network Traffic & C2 Stream Reconstruction | Wireshark, PCAP, TCP Stream Carving | <span class="pill done">Complete</span> |
| **Lab 03** | LSASS Credential Dumping | Splunk SIEM, Sysmon Event ID 10, SPL | <span class="pill done">Complete</span> |
| **Lab 04** | Inbound Phishing & Header Forensics | RFC 822 Headers, CyberChef, Defanging | <span class="pill done">Complete</span> |
| **Lab 05** | Windows Authentication & Brute Force Logic | KQL, Azure Data Explorer, Event ID 4625/4624 | <span class="pill done">Complete</span> |
| **Lab 06** | Automated Threat Intelligence IOC Enrichment Tool | Python 3, VirusTotal API, AbuseIPDB | <span class="pill wip">In Progress</span> |
| **Lab 07** | Active Directory Lab: Password Spraying in Sentinel | VirtualBox, Windows Server DC, Kali, Sentinel KQL | <span class="pill wip">Planned</span> |
| **Lab 08** | Kerberoasting Attack & Detection Engineering | Impacket `GetUserSPNs`, Event ID 4769 (RC4 0x17), SPL/KQL | <span class="pill wip">Planned</span> |
| **Lab 09** | Endpoint Persistence Hunting with Sysmon & Atomic Red Team | Sysmon (SwiftOnSecurity), Event ID 4698, Splunk Dashboard | <span class="pill wip">Planned</span> |
| **Lab 10** | C2 Beacon Hunting with Zeek & RITA | Zeek Network Logs, RITA Jitter Scoring, Wireshark | <span class="pill wip">Planned</span> |