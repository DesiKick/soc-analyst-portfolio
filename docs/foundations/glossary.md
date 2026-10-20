---
title: Glossary
---

# Glossary

Every technical term used in this portfolio, explained in plain English.

---

## Core Security Operations

| Term | Plain-English meaning |
| :--- | :--- |
| **SOC** (Security Operations Center) | The team that monitors a company's systems for attacks and responds to them |
| **Alert** | An automatic warning raised when activity matches a pattern that might be an attack |
| **Triage** | Quickly deciding whether an alert is real and how urgent it is |
| **True positive** | An alert that correctly caught real malicious activity |
| **False positive** | An alert that fired on something harmless. Too many of these bury the real attacks |
| **Benign true positive** | The alert was technically correct, but the activity was authorized, like an admin doing approved maintenance |
| **Incident** | A confirmed security event that needs a response |
| **Escalation** | Handing a serious case to a more senior team, usually incident response |
| **Containment** | Stopping an attack from spreading: disabling an account, isolating a computer, blocking an address |
| **Playbook** | A step-by-step guide for responding to a specific type of incident |
| **Threat hunting** | Searching for attackers proactively, before any alert fires |
| **Detection / detection rule** | A saved search that runs automatically and raises an alert when it finds a match |
| **Detection engineering** | Writing, testing, and tuning those rules |
| **Tuning** | Adjusting a rule so it stops firing on harmless activity without missing real attacks |
| **MTTD / MTTR** | Mean time to detect and mean time to respond: how fast the team notices and stops an attack |

## Tools

| Term | Plain-English meaning |
| :--- | :--- |
| **SIEM** | A central system that collects logs from everywhere and lets analysts search them. Splunk and Microsoft Sentinel are SIEMs |
| **Splunk** | A widely used SIEM. Its search language is **SPL** |
| **Microsoft Sentinel** | Microsoft's cloud SIEM. Its search language is **KQL** |
| **Azure Data Explorer** | A Microsoft data service that also uses KQL; I used its free tier to test queries |
| **EDR** | Software on each computer that watches program behavior and can isolate the machine. CrowdStrike Falcon is an EDR |
| **SOAR** | Automation that performs routine response steps without an analyst doing them by hand |
| **Sysmon** | A free Microsoft tool that records detailed activity on Windows: programs starting, network connections, file changes |
| **Wireshark** | A tool for opening and reading recordings of network traffic |
| **CyberChef** | A web tool for decoding and transforming data, often used on suspicious email content |
| **Sigma** | A shared format for writing detection rules once and converting them to any SIEM |
| **Regex** (regular expression) | A pattern for finding and pulling specific text out of messy data |

## Windows and Logs

| Term | Plain-English meaning |
| :--- | :--- |
| **Log** | A timestamped record of something that happened on a computer |
| **Event ID** | The number Windows assigns to each type of log entry. 4625 means "failed logon," for example. See the [Event ID Reference](event-reference.md) |
| **Process** | A running program |
| **Parent / child process** | The program that started another program, and the program it started. Word starting PowerShell is a classic warning sign |
| **Baseline** | What normal looks like, so abnormal stands out |
| **Logon type** | How someone logged in: at the keyboard, over the network, or by remote desktop |
| **Domain controller** | The server that manages every account and login in a company network. Compromise it and you control the company |
| **Active Directory** | Microsoft's system for managing users, computers, and permissions across a company |
| **LSASS** | The Windows process that holds logged-in users' passwords and login tickets in memory. Attackers try to copy it to steal credentials |
| **Memory dump** | A copy of a program's memory saved to a file. A dump of LSASS contains passwords |
| **LOLBin** (living off the land binary) | A legitimate Windows tool abused by attackers, so their activity blends in. `rundll32` and `regasm` are examples |

## Attacks

| Term | Plain-English meaning |
| :--- | :--- |
| **Credential dumping** | Stealing stored passwords or login tickets from a computer |
| **Brute force** | Guessing passwords over and over until one works |
| **Password spraying** | Trying one or two common passwords across many accounts, to avoid locking any single account out |
| **Phishing** | Fake emails pretending to come from a trusted source, to steal passwords or install malware |
| **Spoofing** | Faking the sender of an email so it looks legitimate |
| **Typosquatting** | Using a name that looks almost right, like "Netllx" instead of "Netflix" |
| **Tracking pixel** | An invisible image in an email that tells the sender when you opened it |
| **Macro** | Code embedded in an Office document. Attackers use it to run malware when "Enable Content" is clicked |
| **Lateral movement** | An attacker spreading from one compromised computer to others |
| **C2** (command and control) | The channel an attacker uses to send instructions to a compromised computer |
| **Masquerading** | Disguising a malicious tool, for example by renaming it |

## Analysis

| Term | Plain-English meaning |
| :--- | :--- |
| **IOC** (indicator of compromise) | A clue that an attack happened: a malicious IP address, domain, file hash, or file name |
| **Defanging** | Rewriting a dangerous link so it cannot be clicked by accident, like `hxxp://bad[.]com` |
| **Hash** (MD5, SHA256) | A unique fingerprint of a file. If the hash matches a known malware sample, the file is that malware |
| **Packet / PCAP** | A packet is one small piece of network traffic. A PCAP file is a recording of many packets |
| **HTTP vs HTTPS** | Web traffic. HTTP is readable by anyone watching the network; HTTPS is encrypted |
| **User-Agent** | A label a program sends to websites saying what it is, like "Chrome on Windows" |
| **SPF / DKIM / DMARC** | Email authentication checks that verify a message really came from the domain it claims |
| **Timeline** | The attack events put in order, minute by minute |
| **MITRE ATT&CK** | A public catalog of attacker techniques, each with an ID like T1110 (Brute Force). The industry's shared vocabulary. See my [coverage map](attack-coverage.md) |
| **Correlation** | Linking separate events together, like many failed logins followed by a success from the same address |
