---
title: Lab Environment
---

# Lab Environment

Where every lab's data came from and what it ran on. I'm explicit about this because a detection is only as credible as the data it was tested against.

---

## Data Sources by Lab

| Lab | Data | Where it came from | Analyzed in | Real or simulated |
| :--- | :--- | :--- | :--- | :--- |
| [01 Process Auditing](../investigations/lab-01-windows-process.md) | Windows Security log (4688) | My workstation, `DESKTOP-2UVTUII`, with process auditing enabled | Event Viewer | Real, benign baseline |
| [02 Network Traffic](../investigations/lab-02-network-traffic.md) | PCAP (`http.cap`) | Public Wireshark sample capture | Wireshark | Real capture, public sample |
| [03 LSASS Dumping](../investigations/lab-03-splunk-lsass.md) | Sysmon XML, 7,974 events | Splunk Attack Range telemetry: two domain controllers attacked with Atomic Red Team T1003.001 | Splunk Enterprise (SPL) | Real attack telemetry |
| [04 Phishing](../investigations/lab-04-phishing-analysis.md) | Email headers and bodies | TryHackMe Phishing Analysis module samples | Manual header analysis, CyberChef | Real phishing samples, training set |
| [05 Brute Force](../investigations/lab-05-sentinel-bruteforce.md) | Windows Security log (4625) and a hand-built dataset | My workstation, plus a `datatable` I wrote | Azure Data Explorer (KQL), Event Viewer | Logic tested on simulated data, plus one real local test |

Raw evidence for Labs 02 and 03 is in the repo's [`evidence/`](https://github.com/DesiKick/soc-analyst-portfolio/tree/main/evidence) folder.

---

## How the Data Flows

| Stage | Labs 01 and 05 | Lab 02 | Lab 03 | Lab 04 |
| :--- | :--- | :--- | :--- | :--- |
| **Source** | My workstation | Public PCAP | Attack Range domain controllers | TryHackMe samples |
| **Data** | Windows Security log | Network packets | Sysmon (raw XML) | Email headers and bodies |
| **Analyzed in** | Event Viewer, Azure Data Explorer (KQL) | Wireshark | Splunk, with `rex` field extraction | Header analysis, CyberChef |
| **Output** | Write-up and detection rule | Write-up and detection logic | Write-up and validated detection | Write-up and IOC block list |

Detection rules from every lab are saved in the repo's [`detections/`](https://github.com/DesiKick/soc-analyst-portfolio/tree/main/detections) folder.

---

## Logging I Turn On First

These settings decide what an investigation can see. On any new Windows host I check them first:

| Setting | Why |
| :--- | :--- |
| Audit Process Creation (Success) | Produces Event ID 4688 for every new process |
| Include command line in process creation events | Without it, 4688 shows `powershell.exe` but not what it ran |
| Audit Logon (Success and Failure) | Produces 4624 and 4625 for brute force and lateral movement work |
| PowerShell Script Block Logging | Produces Event ID 4104 with the deobfuscated script content |
| Sysmon with a community config | Adds hashes, network connections (3), process access (10), file creation (11), and DNS (22) |

---

## Planned Home Lab Build

The next step is a small Active Directory lab so future labs run on telemetry I generate end to end:

| Component | Purpose | Status |
| :--- | :--- | :--- |
| Windows Server domain controller | Realistic AD authentication and Kerberos events | <span class="pill wip">Planned</span> |
| Windows 10/11 client with Sysmon | Endpoint telemetry | <span class="pill wip">Planned</span> |
| Kali Linux attacker VM | Generate brute force, spraying, and lateral movement | <span class="pill wip">Planned</span> |
| Microsoft Sentinel workspace with Azure Monitor Agent | Run the Lab 05 rules on real data (Lab 05 v2) | <span class="pill wip">Planned</span> |
