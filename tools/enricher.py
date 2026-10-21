#!/usr/bin/env python3
"""
SOC Automation Tool: Threat Intelligence IOC Enricher
Author: Mian Talha Nayyar
Description: Automates triage enrichment for IPs, domains, and file hashes via
             AbuseIPDB and VirusTotal v3 REST APIs. Outputs defanged markdown
             reports suitable for SOC ticketing systems.
"""

import os
import re
import sys
import argparse
import requests
from typing import Dict, List, Any

# Regular Expression Patterns for IOC Detection
REGEX_IPV4 = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
REGEX_SHA256 = r"^[a-fA-F0-9]{64}$"
REGEX_DOMAIN = r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$"

def defang(indicator: str) -> str:
    """Safely defangs IP addresses, domains, and URLs for ticket documentation."""
    defanged = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return defanged.replace(".", "[.]")

def classify_ioc(indicator: str) -> str:
    """Identifies indicator type based on strict regex patterns."""
    indicator = indicator.strip()
    if re.match(REGEX_IPV4, indicator):
        return "ip"
    elif re.match(REGEX_SHA256, indicator):
        return "hash"
    elif re.match(REGEX_DOMAIN, indicator):
        return "domain"
    return "unknown"

def enrich_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """Queries the AbuseIPDB v2 REST API for IP reputation."""
    if not api_key:
        return {"error": "API Key missing", "score": "N/A", "isp": "Unknown", "usage": "Unknown"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "score": f"{data.get('abuseConfidenceScore', 0)}%",
                "isp": data.get("isp", "Unknown"),
                "country": data.get("countryCode", "Unknown"),
                "total_reports": data.get("totalReports", 0)
            }
        elif response.status_code == 401:
            return {"error": "Invalid API Key", "score": "Auth Error", "isp": "N/A", "total_reports": 0}
        elif response.status_code == 429:
            return {"error": "Rate limited", "score": "Throttled", "isp": "N/A", "total_reports": 0}
        else:
            return {"error": f"HTTP {response.status_code}", "score": "N/A", "isp": "N/A", "total_reports": 0}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "score": "Timeout", "isp": "N/A", "total_reports": 0}

def enrich_virustotal(indicator: str, ioc_type: str, api_key: str) -> Dict[str, Any]:
    """Queries the VirusTotal v3 REST API for hashes, domains, and IPs."""
    if not api_key:
        return {"error": "API Key missing", "malicious": 0, "total": 0, "reputation": "N/A"}
    
    headers = {"x-apikey": api_key}
    
    if ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        return {"error": "Unsupported type", "malicious": 0, "total": 0}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            return {"malicious": malicious, "suspicious": suspicious, "total": total}
        elif response.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "total": 0, "note": "Not found in VT database"}
        elif response.status_code == 429:
            return {"error": "Rate limited", "malicious": "N/A", "total": "N/A"}
        else:
            return {"error": f"HTTP {response.status_code}", "malicious": "N/A", "total": "N/A"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "malicious": "N/A", "total": "N/A"}

def generate_report(iocs: List[str], abuse_key: str, vt_key: str, output_file: str = None) -> str:
    """Processes each IOC, extracts threat scores, and compiles a Markdown table."""
    results = []
    
    print(f"\n[*] Starting IOC Enrichment across {len(iocs)} indicators...\n")
    
    for raw_ioc in iocs:
        raw_ioc = raw_ioc.strip()
        if not raw_ioc:
            continue
        
        ioc_type = classify_ioc(raw_ioc)
        defanged_ioc = defang(raw_ioc)
        verdict = "Undetermined"
        vt_score = "N/A"
        abuse_score = "N/A"
        details = "Manual Review Required"
        
        print(f"[-] Enriching {ioc_type.upper()}: {defanged_ioc}")
        
        if ioc_type == "ip":
            # AbuseIPDB
            abuse_res = enrich_abuseipdb(raw_ioc, abuse_key)
            abuse_score = abuse_res.get("score", "N/A")
            isp = abuse_res.get("isp", "Unknown")
            
            # VirusTotal
            vt_res = enrich_virustotal(raw_ioc, "ip", vt_key)
            vt_mal = vt_res.get("malicious", 0)
            vt_tot = vt_res.get("total", 0)
            vt_score = f"{vt_mal}/{vt_tot}" if vt_tot != "N/A" else "Throttled"
            
            # Scoring logic
            conf = int(abuse_res.get("score", "0%").replace("%", "")) if "%" in str(abuse_res.get("score")) else 0
            if conf >= 80 or (isinstance(vt_mal, int) and vt_mal >= 5):
                verdict = "MALICIOUS"
                details = f"AbuseIPDB Conf: {conf}% | ISP: {isp}"
            elif conf > 0 or (isinstance(vt_mal, int) and vt_mal > 0):
                verdict = "SUSPICIOUS"
                details = f"Abuse reports: {abuse_res.get('total_reports', 0)} | ISP: {isp}"
            else:
                verdict = "BENIGN / CLEAN"
                details = f"Zero detections across vendors | ISP: {isp}"
                
        elif ioc_type in ["domain", "hash"]:
            vt_res = enrich_virustotal(raw_ioc, ioc_type, vt_key)
            vt_mal = vt_res.get("malicious", 0)
            vt_tot = vt_res.get("total", 0)
            vt_score = f"{vt_mal}/{vt_tot}" if vt_tot != "N/A" else "Throttled"
            
            if isinstance(vt_mal, int) and vt_mal >= 5:
                verdict = "MALICIOUS"
                details = f"Flagged by {vt_mal} AV detection engines"
            elif isinstance(vt_mal, int) and vt_mal > 0:
                verdict = "SUSPICIOUS"
                details = f"Low engine detection ({vt_mal} flags)"
            elif vt_res.get("note") == "Not found in VT database":
                verdict = "UNKNOWN"
                details = "No existing intelligence records in VirusTotal"
            else:
                verdict = "BENIGN / CLEAN"
                details = "Zero detections across global telemetry"
        else:
            verdict = "INVALID"
            details = "Unrecognized IOC syntax"

        results.append({
            "defanged": defanged_ioc,
            "type": ioc_type.upper(),
            "vt_score": vt_score,
            "abuse_score": abuse_score,
            "verdict": verdict,
            "details": details
        })

    # Compile Markdown Table
    md = "### Incident Response Automated IOC Enrichment Report\n\n"
    md += "| Defanged Indicator | Type | VirusTotal Detections | AbuseIPDB Confidence | SOC Triage Verdict | Forensic Context |\n"
    md += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
    for r in results:
        badge = r['verdict']
        if r['verdict'] == "MALICIOUS":
            badge = f"<span style='color:#ef4444;font-weight:bold;'>MALICIOUS</span>"
        elif r['verdict'] == "SUSPICIOUS":
            badge = f"<span style='color:#f59e0b;font-weight:bold;'>SUSPICIOUS</span>"
        elif "BENIGN" in r['verdict']:
            badge = f"<span style='color:#10b981;font-weight:bold;'>BENIGN</span>"

        md += f"| `{r['defanged']}` | {r['type']} | {r['vt_score']} | {r['abuse_score']} | {badge} | {r['details']} |\n"

    print("\n[+] Enrichment complete. Ticket table generated.\n")
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[+] Report exported to: {output_file}")
    
    return md

def main():
    parser = argparse.ArgumentParser(description="Enrich threat indicators using VirusTotal and AbuseIPDB APIs.")
    parser.add_argument("-i", "--iocs", nargs="+", help="One or more IOCs separated by spaces")
    parser.add_argument("-f", "--file", help="File containing list of IOCs (one per line)")
    parser.add_argument("-o", "--output", help="Save the output markdown table to a file")
    args = parser.parse_args()

    # Load API keys from environment variables (Prevent credential leakage in GitHub)
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not abuse_key and not vt_key:
        print("[!] WARNING: Neither ABUSEIPDB_API_KEY nor VIRUSTOTAL_API_KEY environment variables are set.")
        print("[!] Running in offline mock evaluation mode.\n")

    ioc_list = []
    if args.iocs:
        ioc_list.extend(args.iocs)
    if args.file and os.path.exists(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            ioc_list.extend([line.strip() for line in f if line.strip()])

    if not ioc_list:
        # Default test dataset from our portfolio investigations:
        # Lab 03: Credential dumper hash
        # Lab 04: Sultanbogor delivery phishing domain, devret redirect
        # Lab 05: Attacker internal/pivot IP
        ioc_list = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sultanbogor.com",
            "devret.xyz",
            "185.220.101.5",
            "192.168.10.45"
        ]

    report = generate_report(ioc_list, abuse_key, vt_key, args.output)
    print(report)

if __name__ == "__main__":
    main()