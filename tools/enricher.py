#!/usr/bin/env python3
"""
IOC Enricher: threat intelligence lookups for SOC triage.
Author: Mian Talha Nayyar

Takes IP addresses, domains, and file hashes, looks them up in VirusTotal (v3)
and AbuseIPDB (v2), assigns a triage verdict, defangs every indicator, and
writes a ticket-ready Markdown report.

Design rules:
  * Fail closed: an indicator is only marked CLEAN when at least one source
    actually returned data. Missing keys or API errors give NO DATA, never CLEAN.
  * Private and reserved IPs are never sent to external APIs.
  * API keys are read from environment variables, never from code or arguments.

Usage:
  python tools/enricher.py -i 8.8.8.8 example.com
  python tools/enricher.py -f iocs.txt -o report.md
  python tools/enricher.py --lab-set -o report.md
"""

import argparse
import ipaddress
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

VT_URLS = {
    "ip": "https://www.virustotal.com/api/v3/ip_addresses/{}",
    "domain": "https://www.virustotal.com/api/v3/domains/{}",
    "hash": "https://www.virustotal.com/api/v3/files/{}",
}
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,63}$")

# Indicators from earlier portfolio labs, plus one known-good and one known-bad control.
LAB_SET = [
    ("7234C8F98B87593641BBDB594E34C94B9436986C4FB70E7DA5BCECFF147D14C3", "Lab 03: binary that opened LSASS 38 times"),
    ("sultanbogor.com", "Lab 04: envelope sender domain in PayPal lure"),
    ("musacombi.online", "Lab 04: sender domain in Netflix lure"),
    ("devret.xyz", "Lab 04: tracking pixel host"),
    ("192.168.10.45", "Lab 05: simulated attacker IP (private)"),
    ("8.8.8.8", "Control: known-good public DNS server"),
    ("185.220.101.5", "Control: public IP from abuse feeds, expected to flag"),
]

VT_MALICIOUS = 5      # engines flagging malicious for a MALICIOUS verdict
ABUSE_MALICIOUS = 75  # AbuseIPDB confidence for a MALICIOUS verdict
ABUSE_SUSPICIOUS = 25


def refang(raw: str) -> str:
    """Accept indicators pasted in defanged form, like hxxp://bad[.]com."""
    s = raw.strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    s = re.sub(r"^hxxps?://", "", s, flags=re.I)
    s = re.sub(r"^https?://", "", s, flags=re.I)
    return s.split("/")[0] if not RE_SHA256.match(s) else s


def defang(indicator: str) -> str:
    """Make an indicator safe to paste into tickets and chat."""
    return indicator.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def classify(indicator: str) -> str:
    try:
        ip = ipaddress.ip_address(indicator)
        return "private_ip" if (ip.is_private or ip.is_reserved or ip.is_loopback) else "ip"
    except ValueError:
        pass
    if RE_SHA256.match(indicator) or RE_SHA1.match(indicator) or RE_MD5.match(indicator):
        return "hash"
    if RE_DOMAIN.match(indicator):
        return "domain"
    return "unknown"


def query_virustotal(indicator: str, ioc_type: str, key: str, session=requests) -> dict:
    if not key:
        return {"ok": False, "note": "no VirusTotal key"}
    try:
        r = session.get(VT_URLS[ioc_type].format(indicator), headers={"x-apikey": key}, timeout=15)
    except requests.RequestException as e:
        return {"ok": False, "note": f"VT error: {type(e).__name__}"}
    if r.status_code == 404:
        return {"ok": True, "found": False}
    if r.status_code == 429:
        return {"ok": False, "note": "VT rate limited"}
    if r.status_code == 401:
        return {"ok": False, "note": "VT key rejected"}
    if r.status_code != 200:
        return {"ok": False, "note": f"VT HTTP {r.status_code}"}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ok": True, "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "total": sum(int(v) for v in stats.values() if isinstance(v, int)),
        "names": attrs.get("meaningful_name") or "",
    }


def query_abuseipdb(ip: str, key: str, session=requests) -> dict:
    if not key:
        return {"ok": False, "note": "no AbuseIPDB key"}
    try:
        r = session.get(ABUSE_URL, headers={"Accept": "application/json", "Key": key},
                        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
    except requests.RequestException as e:
        return {"ok": False, "note": f"AbuseIPDB error: {type(e).__name__}"}
    if r.status_code == 429:
        return {"ok": False, "note": "AbuseIPDB rate limited"}
    if r.status_code == 401:
        return {"ok": False, "note": "AbuseIPDB key rejected"}
    if r.status_code != 200:
        return {"ok": False, "note": f"AbuseIPDB HTTP {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "ok": True,
        "score": int(d.get("abuseConfidenceScore", 0)),
        "reports": int(d.get("totalReports", 0)),
        "isp": d.get("isp") or "unknown ISP",
        "country": d.get("countryCode") or "??",
        "tor": bool(d.get("isTor", False)),
    }


def verdict_for(vt: dict, ab: dict) -> str:
    """Fail closed: CLEAN only when a source answered and nothing was flagged."""
    vt_mal = vt.get("malicious", 0) if vt.get("ok") else 0
    vt_sus = vt.get("suspicious", 0) if vt.get("ok") else 0
    ab_score = ab.get("score", 0) if ab.get("ok") else 0
    if vt_mal >= VT_MALICIOUS or ab_score >= ABUSE_MALICIOUS:
        return "MALICIOUS"
    if vt_mal > 0 or vt_sus > 0 or ab_score >= ABUSE_SUSPICIOUS:
        return "SUSPICIOUS"
    answered = (vt.get("ok") and vt.get("found")) or ab.get("ok")
    if answered:
        return "CLEAN"
    if vt.get("ok") and vt.get("found") is False:
        return "NOT FOUND"
    return "NO DATA"


def fmt_vt(vt: dict) -> str:
    if not vt:
        return "not queried"
    if not vt.get("ok"):
        return vt["note"]
    if not vt.get("found"):
        return "not in VirusTotal"
    return f"{vt['malicious']}/{vt['total']} malicious"


def fmt_ab(ab: dict) -> str:
    if not ab:
        return "n/a"
    if not ab.get("ok"):
        return ab["note"]
    tor = ", Tor exit" if ab["tor"] else ""
    return f"{ab['score']}% ({ab['reports']} reports, {ab['country']}{tor})"


def enrich(iocs, vt_key, abuse_key, vt_delay=15.0, session=requests, sleep=time.sleep, log=print):
    rows, vt_calls = [], 0
    for raw, context in iocs:
        ind = refang(raw)
        kind = classify(ind)
        vt, ab = {}, {}
        log(f"[-] {kind.upper():<10} {defang(ind)}")
        if kind == "private_ip":
            verdict, vt, ab = "INTERNAL", {"ok": False, "note": "private IP, not sent to APIs"}, {}
        elif kind == "unknown":
            verdict = "INVALID"
            vt = {"ok": False, "note": "unrecognized format"}
        else:
            if vt_key:
                if vt_calls and vt_delay:
                    sleep(vt_delay)  # VirusTotal free tier allows 4 requests per minute
                vt_calls += 1
            vt = query_virustotal(ind, kind, vt_key, session)
            if kind == "ip":
                ab = query_abuseipdb(ind, abuse_key, session)
            verdict = verdict_for(vt, ab)
        rows.append({"ioc": defang(ind), "type": kind.replace("_", " "), "vt": fmt_vt(vt),
                     "abuse": fmt_ab(ab), "verdict": verdict, "context": context})
    return rows


def to_markdown(rows, elapsed: float, sources: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"**Generated:** {stamp} | **Indicators:** {len(rows)} | **Run time:** {elapsed:.1f} s | **Sources:** {sources}", "",
           "| Indicator (defanged) | Type | VirusTotal | AbuseIPDB | Verdict | Context |",
           "| :--- | :--- | :--- | :--- | :--- | :--- |"]
    for r in rows:
        out.append(f"| `{r['ioc']}` | {r['type']} | {r['vt']} | {r['abuse']} | **{r['verdict']}** | {r['context']} |")
    return "\n".join(out) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description="Enrich IOCs with VirusTotal and AbuseIPDB.")
    p.add_argument("-i", "--iocs", nargs="+", help="indicators separated by spaces (defanged input is fine)")
    p.add_argument("-f", "--file", help="file with one indicator per line")
    p.add_argument("--lab-set", action="store_true", help="run the portfolio test set from Labs 03 to 05")
    p.add_argument("-o", "--output", help="write the Markdown report to this file")
    p.add_argument("--vt-delay", type=float, default=15.0, help="seconds between VirusTotal calls (free tier: 15)")
    a = p.parse_args(argv)

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not vt_key and not abuse_key:
        print("[!] No API keys found. Set VIRUSTOTAL_API_KEY and ABUSEIPDB_API_KEY first.")
        print("[!] Every indicator will show NO DATA until keys are set.\n")

    iocs = []
    if a.lab_set:
        iocs += LAB_SET
    if a.iocs:
        iocs += [(x, "") for x in a.iocs]
    if a.file:
        with open(a.file, encoding="utf-8") as fh:
            iocs += [(line.strip(), "") for line in fh if line.strip() and not line.startswith("#")]
    if not iocs:
        p.error("give indicators with -i, -f, or --lab-set")

    sources = ", ".join(s for s, k in (("VirusTotal", vt_key), ("AbuseIPDB", abuse_key)) if k) or "none (no keys set)"
    print(f"[*] Enriching {len(iocs)} indicators | sources: {sources}\n")
    t0 = time.perf_counter()
    rows = enrich(iocs, vt_key, abuse_key, a.vt_delay)
    elapsed = time.perf_counter() - t0
    md = to_markdown(rows, elapsed, sources)
    print("\n" + md)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"[+] Report saved to {a.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
