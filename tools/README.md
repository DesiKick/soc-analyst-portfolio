# IOC Enricher

A command-line tool that looks up IP addresses, domains, and file hashes in **VirusTotal** and **AbuseIPDB**, assigns a triage verdict, defangs every indicator, and writes a ticket-ready Markdown report.

Write-up: [Lab 06 on the portfolio site](https://desikick.github.io/soc-analyst-portfolio/investigations/lab-06-python-enrichment/)

## What it does

| Feature | Detail |
| :--- | :--- |
| Indicator types | IPv4/IPv6, domains, MD5 / SHA1 / SHA256 hashes. Accepts defanged input like `hxxp://bad[.]com` |
| Sources | VirusTotal v3 (all types), AbuseIPDB v2 (public IPs) |
| Verdicts | MALICIOUS, SUSPICIOUS, CLEAN, NOT FOUND, NO DATA, INTERNAL, INVALID |
| Fail closed | CLEAN only when a source actually answered. Missing keys, errors, and rate limits give NO DATA |
| Privacy | Private and reserved IPs are never sent to external APIs |
| Rate limits | Waits 15 seconds between VirusTotal calls to respect the free tier (4 per minute) |
| Secrets | API keys are read from environment variables only |

## Setup (Windows PowerShell)

```powershell
pip install requests
$env:VIRUSTOTAL_API_KEY = "paste-your-virustotal-key"
$env:ABUSEIPDB_API_KEY  = "paste-your-abuseipdb-key"
```

Free keys: [VirusTotal](https://www.virustotal.com/gui/join-us) and [AbuseIPDB](https://www.abuseipdb.com/register). The keys last only for the current PowerShell window, so they never end up in a file.

## Usage

```powershell
# Portfolio test set (indicators from Labs 03 to 05 plus two controls)
python tools\enricher.py --lab-set -o report.md

# Your own indicators
python tools\enricher.py -i 8.8.8.8 hxxp://devret[.]xyz

# A file with one indicator per line
python tools\enricher.py -f iocs.txt -o report.md
```

## Tests

12 offline tests with fake API responses. No keys or internet needed:

```powershell
python -m unittest discover -s tools -v
```
