# SOC Automation Suite: Threat Intelligence IOC Enricher

An automated command-line Python utility engineered to triage indicators of compromise (IPs, domains, and SHA256 hashes) using the AbuseIPDB v2 and VirusTotal v3 REST APIs.

## Capabilities
* **Automatic Indicator Classification:** Applies strict regex evaluation for IPv4, SHA256 file digests, and fully qualified domain names (FQDNs).
* **Indicator Defanging:** Automatically sanitizes indicators (`hxxp://`, `[.]`) to ensure safe pasting into ticketing platforms (Jira, ServiceNow) without triggering URL click filters.
* **Reputation Correlation:** Collects real-time detection ratios, AbuseIPDB confidence scores, ISP classification, and historical abuse reports.
* **Ticket Markdown Export:** Formats results into structured, copy-pasteable Markdown tables.

## Environment Setup & API Configuration

To keep API credentials out of source control, the script reads keys from environment variables:

### Windows (PowerShell)
```powershell
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key_here"
$env:VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"