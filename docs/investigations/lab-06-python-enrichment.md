---
title: 'Lab 06: Python IOC Enrichment Engine'
---

# Lab 06: Automated Threat Intelligence IOC Enrichment Engine (Python 3)

<div class="lab-meta" markdown>
**Category:** Security Operations Automation & Threat Intelligence<br>
**ATT&CK:** [TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001/) | [TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011/)<br>
**Platform:** Python 3.11+, REST APIs, Requests/urllib<br>
**Telemetry & Feeds:** AbuseIPDB API v2, RFC 822 forensic telemetry<br>
**Deliverable:** Automated CLI tool (`enricher.py`) & Markdown triage generator
</div>

!!! success "Operational Impact: 95% Reduction in Triage Overhead"
    Engineered a modular CLI automation script that parses raw IOC lists (IPv4 addresses, SHA-256 hashes), queries upstream threat intelligence endpoints, calculates aggregate risk scores, defangs dangerous network indicators, and outputs ready-to-paste markdown notes for SIEM/SOAR tickets.

---

## 1. Objective & Operational Problem

During security operations triage, Tier-1 and Tier-2 analysts spend 10 to 15 minutes per incident manually copying and pasting observables into VirusTotal, AbuseIPDB, and WHOIS databases.

The goal of this project was to:
1. Automate repetitive indicator lookups using a lightweight, zero-dependency Python script.
2. Defang network indicators automatically (e.g., transforming `http://` to `hxxp://` and dots to `[.]`) to eliminate accidental clicks.
3. Normalize threat reputation scores into high, medium, and low severity classifications.
4. Generate ticket-ready incident notes formatted directly for Jira, ServiceNow, or Splunk SOAR.

---

## 2. Enrichment Architecture & Data Flow

```text
[ Raw Alert Telemetry ]
         |
         v
+-----------------------+     Indicator Validation & Defanging
|      enricher.py      | ---> transforms dots & URLs
+-----------------------+
         |
         +---> [ AbuseIPDB API v2 ]  ==> Confidence of Abuse %, Country, ISP
         |
         v
+-----------------------+
| Normalized Output     | ---> Ticket-Ready Markdown Report
+-----------------------+