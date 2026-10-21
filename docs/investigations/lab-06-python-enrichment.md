---
title: 'Lab 06: Automated Threat Intelligence IOC Enrichment Tool'
---

# Lab 06: Automated Threat Intelligence IOC Enrichment Tool (Python 3)

<div class="lab-meta" markdown>
**Category:** Security Operations Automation & Threat Intelligence<br>
**MITRE ATT&CK:** Cross-cutting triage coverage (Supports all Tactics & Techniques)<br>
**Platform:** Python 3.10+ / RESTful APIs (VirusTotal v3, AbuseIPDB v2)<br>
**Target Artifacts:** IPv4 Addresses, SHA256 Hashes, Fully Qualified Domains (FQDN)<br>
**Source Code:** [`tools/enricher.py`](https://github.com/DesiKick/soc-portfolio/blob/main/tools/enricher.py)
</div>

!!! success "Automation Impact: 15-Minute Investigations Reduced to 15-Second Actions"
    Manual indicator verification across external reputation sites introduces significant operational latency and human error into Tier-1 alert queues. This Python utility automatically parses, defangs, scores, and formats multi-source threat intelligence telemetry into ticket-ready Markdown tables, reducing mean time to triage (MTTT) from 15 minutes to under 15 seconds per incident.

---

## 1. Operational Problem & Engineering Objective

In an enterprise SOC handling dozens of daily alerts from EDR, firewalls, and email security gateways, analysts spend substantial manual effort:
1. Copying raw IPs, domains, and hashes from logs.
2. Defanging indicators manually to avoid accidental execution or triggering enterprise proxy blocks.
3. Querying multiple web portals (VirusTotal, AbuseIPDB, Whois) one by one.
4. Manually typing findings into Jira or ServiceNow incident tickets.

**Engineering Goal:** Develop a modular, portable Python 3 automation script that:
* Accepts indicators via direct CLI arguments or flat files.
* Applies strict regex patterns to categorize IPs, domains, and SHA256 hashes.
* Safely defangs all indicators before reporting.
* Queries the **AbuseIPDB v2** and **VirusTotal v3** REST APIs.
* Enforces strict API credential security via local environment variables to prevent accidental GitHub leaks.
* Compiles an executive-grade Markdown table formatted for SOC tickets.

---

## 2. Tested Indicators of Compromise (Cross-Lab Verification)

The tool was evaluated against real indicators identified during previous portfolio investigations:

| Indicator of Compromise | Source Lab | Indicator Type | Expected Forensic Context |
| :--- | :--- | :--- | :--- |
| `sultanbogor.com` | **Lab 04 (Phishing)** | Domain | Compromised domain hosting weaponized lure redirects. |
| `devret.xyz` | **Lab 04 (Phishing)** | Domain | Ephemeral `.xyz` domain serving credential harvesting forms. |
| `185.220.101.5` | **Lab 02 (Network C2)** | IPv4 Address | Known Tor exit node associated with C2 beaconing. |
| `192.168.10.45` | **Lab 05 (Sentinel)** | IPv4 Address | RFC 1918 internal IP used during SMB dictionary brute-force. |
| `e3b0c44298fc1c14...` | **Lab 03 (LSASS)** | SHA256 Hash | Baseline file hash extracted during credential dumping triage. |

---

## 3. Automation Architecture & Defanging Logic

### Indicator Defanging Logic
Indicators must be neutralized before being placed into documentation. The script applies regex transformations to replace live schemes with `hxxp://` and wrap all dots in brackets `[.]`:

```python
def defang(indicator: str) -> str:
    """Neutralizes clickable links and actionable IP strings."""
    defanged = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return defanged.replace(".", "[.]")