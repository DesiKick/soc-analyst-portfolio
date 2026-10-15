# SOC Analyst Portfolio | Mian Talha Nayyar

Hands-on SOC investigations, threat hunting, and detection engineering. Every lab goes from raw telemetry to a verdict and a detection.

**Live site:** https://desikick.github.io/soc-analyst-portfolio/

## Labs

| # | Investigation | Focus | Tools | ATT&CK |
|---|---|---|---|---|
| 01 | [Windows Process Auditing](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-01-windows-process/) | Process lineage, Event ID 4688 | Event Viewer, Audit Policy | T1059 |
| 02 | [Network Traffic Analysis](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-02-network-traffic/) | Cleartext HTTP, stream reconstruction | Wireshark | T1071.001 |
| 03 | [LSASS Credential Dumping](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-03-splunk-lsass/) | Threat hunt plus validated detection | Splunk, SPL, Sysmon | T1003.001 |
| 04 | [Phishing Email Analysis](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-04-phishing-analysis/) | Header forensics, IOC extraction | CyberChef, header analysis | T1566 |

## Repo layout

```
docs/          Site content (MkDocs Material)
detections/    Detection rules as SPL and Sigma
evidence/      Raw lab data (Sysmon logs, PCAPs) so results can be reproduced
.github/       GitHub Actions workflow that builds and deploys the site
```

## Run locally

```bash
pip install mkdocs-material
mkdocs serve
```

Pushing to `main` rebuilds and deploys the site automatically.

## Contact

- LinkedIn: [linkedin.com/in/mian-nayyar](https://www.linkedin.com/in/mian-nayyar)
- Email: talha397@gmail.com
