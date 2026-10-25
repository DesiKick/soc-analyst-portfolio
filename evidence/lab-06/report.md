**Generated:** 2026-10-25 19:18 UTC | **Indicators:** 7 | **Run time:** 81.7 s | **Sources:** VirusTotal, AbuseIPDB

| Indicator (defanged) | Type | VirusTotal | AbuseIPDB | Verdict | Context |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `7234C8F98B87593641BBDB594E34C94B9436986C4FB70E7DA5BCECFF147D14C3` | hash | 55/76 malicious | n/a | **MALICIOUS** | Lab 03: binary that opened LSASS 38 times |
| `sultanbogor[.]com` | domain | 0/92 malicious | n/a | **CLEAN** | Lab 04: envelope sender domain in PayPal lure |
| `musacombi[.]online` | domain | 0/92 malicious | n/a | **CLEAN** | Lab 04: sender domain in Netflix lure |
| `devret[.]xyz` | domain | 0/92 malicious | n/a | **SUSPICIOUS** | Lab 04: tracking pixel host |
| `192[.]168[.]10[.]45` | private ip | private IP, not sent to APIs | n/a | **INTERNAL** | Lab 05: simulated attacker IP (private) |
| `8[.]8[.]8[.]8` | ip | 0/92 malicious | 0% (242 reports, US) | **CLEAN** | Control: known-good public DNS server |
| `185[.]220[.]101[.]5` | ip | 11/92 malicious | 100% (410 reports, DE, Tor exit) | **MALICIOUS** | Control: public IP from abuse feeds, expected to flag |
