# SOC Analyst Portfolio | Mian Talha Nayyar

[![Build, test and deploy](https://github.com/DesiKick/soc-analyst-portfolio/actions/workflows/deploy.yml/badge.svg)](https://github.com/DesiKick/soc-analyst-portfolio/actions/workflows/deploy.yml)

Hands-on SOC investigations, threat hunting, detection engineering, and cloud incident response. Every lab goes from raw telemetry to a verdict and a detection, with the evidence attached so the results can be checked.

**Live site:** https://desikick.github.io/soc-analyst-portfolio/

### Start here

If you only read three, read these: **[Lab 03 - LSASS Credential Dumping](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-03-splunk-lsass/)** (my strongest detection work), **[Lab 09 - Compromised IAM Key in AWS](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-09-aws-iam-compromise/)**, and **[Lab 10 - Automated IR in AWS](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-10-aws-automated-ir/)**.

## Investigations

| # | Investigation | Focus | Tools | ATT&CK |
|---|---|---|---|---|
| 01 | [Windows Process Auditing](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-01-windows-process/) | Process lineage, Event ID 4688 | Event Viewer, Audit Policy | T1059 |
| 02 | [Network Traffic Analysis](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-02-network-traffic/) | Cleartext HTTP, stream reconstruction | Wireshark | T1071.001 |
| 03 | [LSASS Credential Dumping](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-03-splunk-lsass/) | Threat hunt + validated detection | Splunk, SPL, Sysmon | T1003.001 |
| 04 | [Phishing Email Analysis](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-04-phishing-analysis/) | Header forensics, IOC extraction | CyberChef, header analysis | T1566 |
| 05 | [Brute Force Detection Logic](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-05-sentinel-bruteforce/) | Failure-then-success correlation, spraying | KQL, Azure Data Explorer | T1110 |
| 06 | [Python IOC Enrichment Tool](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-06-python-enrichment/) | Automated IOC lookups, fail-closed design, unit tests | Python, VirusTotal, AbuseIPDB | Supports all tactics |
| 07 | [Brute Force on a Real AD Domain](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-07-ad-bruteforce/) | Brute force, spray, and break-in on a live domain | Windows Server DC, Event ID 4625/4624 | T1110.001/.003 |
| 08 | [Kerberoasting Detection](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-08-kerberoasting/) | RC4 service-ticket requests detected in 4769 | Active Directory, Event ID 4769 | T1558.003 |
| 09 | [Compromised IAM Key in AWS](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-09-aws-iam-compromise/) | Leaked-key breach chain rebuilt from CloudTrail; detection + IR runbook | AWS, CloudTrail, IAM, S3 | T1078.004, T1098, T1530 |
| 10 | [Automated IR in AWS](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-10-aws-automated-ir/) | EventBridge + Lambda pipeline that auto-contains a stolen key | AWS, EventBridge, Lambda, CloudTrail | T1078.004, T1496 |

See the [Detection Library](https://desikick.github.io/soc-analyst-portfolio/detections/) for the rules (SPL, Sigma, KQL) and their validation status, and the [ATT&CK Coverage Map](https://desikick.github.io/soc-analyst-portfolio/foundations/attack-coverage/) for what's covered.

## Stack

Splunk · Microsoft Sentinel (KQL) · CrowdStrike · Sysmon · Wireshark · Python · AWS (CloudTrail, IAM, EventBridge, Lambda, S3) · Active Directory · MITRE ATT&CK · MkDocs Material

## Repo layout

```
docs/          Site content (MkDocs Material)
detections/    Detection rules as SPL, Sigma, and KQL
evidence/      Raw lab data so results can be reproduced
tools/         The Python IOC enricher and its unit tests
.github/       GitHub Actions: runs the tests and deploys the site on every push
```

## Run locally

```bash
pip install mkdocs-material
mkdocs serve
```

Every push to `main` runs the enricher's unit tests and, if they pass, builds and deploys the site to GitHub Pages automatically (see the badge above).

## Contact

- LinkedIn: [linkedin.com/in/mian-nayyar](https://www.linkedin.com/in/mian-nayyar)
- Email: talha397@gmail.com
