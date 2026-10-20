---
title: What a SOC Analyst Does
---

# What a SOC Analyst Does

This page explains my job in plain English, for anyone reading this portfolio, technical or not.

---

## The Short Version

A **Security Operations Center (SOC)** is the team that watches over a company's computers, networks, and accounts around the clock, looking for signs of an attack.

Think of a large office building. It has cameras in every hallway, badge readers on every door, and alarms on the windows. Someone has to sit in the security room, watch those feeds, and decide which alarms are real. **A SOC analyst is that person for the company's digital building.**

Every day, security tools generate alerts: "someone failed to log in 40 times," "a program tried to read passwords from memory," "an employee clicked a link in a suspicious email." Most alerts turn out to be harmless. My job is to quickly and correctly separate the real attacks from the noise, stop the real ones before they cause damage, and make the alarms smarter so they cry wolf less often.

---

## How an Alert Becomes a Decision

<div class="flow">
  <div><strong>1. Detect</strong><span>A tool raises an alert</span></div>
  <div><strong>2. Triage</strong><span>Is it real? How serious?</span></div>
  <div><strong>3. Investigate</strong><span>What happened, to whom, and how?</span></div>
  <div><strong>4. Respond</strong><span>Contain, remove, recover, report</span></div>
  <div><strong>5. Improve</strong><span>Tune the rule, close the gap</span></div>
</div>

1. **Detect.** A security tool spots something matching a known pattern of attack and raises an alert.
2. **Triage.** I decide quickly whether it is real and how urgent it is. Many alerts are closed here as harmless, with a written reason.
3. **Investigate.** For anything that might be real, I pull the logs, follow the trail, and reconstruct exactly what happened, in order.
4. **Respond.** If it is an attack, I contain it: disable the stolen account, isolate the infected computer, block the attacker's address. Serious cases are escalated to the incident response team.
5. **Improve.** Every alert teaches something. If the alarm was wrong, I fix the rule. If an attack slipped through, I write a new rule so it gets caught next time.

My method for steps 2 to 4 is written out in [How I Triage an Alert](triage-method.md).

---

## The Tools, Explained Simply

| Tool | What it is | Building analogy | What I use |
| :--- | :--- | :--- | :--- |
| **SIEM** (Security Information and Event Management) | A central search engine that collects logs from every computer, server, and app | The security room where every camera feed is recorded and searchable | Splunk at work; Splunk and Azure Data Explorer in my labs |
| **EDR** (Endpoint Detection and Response) | Software on each computer that watches what programs do, and can isolate a machine | A guard stationed in every office | CrowdStrike Falcon |
| **SOAR** (Security Orchestration, Automation and Response) | Automation that handles repetitive steps, like looking up a suspicious address | A checklist robot that does the routine paperwork | Splunk SOAR, Python |
| **Email security gateway** | Filters incoming email for phishing and malware | The mailroom that screens packages | Used at RTCS |
| **Threat intelligence** | Shared knowledge about known bad addresses, files, and attacker techniques | A list of known troublemakers shared between buildings | VirusTotal, MITRE ATT&CK |

---

## Who Does What in a SOC

| Role | Focus | In the building analogy |
| :--- | :--- | :--- |
| **Tier 1 analyst** | Watches the alert queue, triages, closes harmless alerts, escalates real ones | Watches the camera feeds |
| **Tier 2 analyst** | Deep investigations, builds timelines, leads containment | Investigates the break-in |
| **Tier 3 / threat hunter** | Proactively searches for attackers no alert has caught yet | Walks the halls looking for anything off |
| **Detection engineer** | Writes and tunes the rules that create alerts | Decides where cameras and alarms go |
| **Incident responder** | Takes over confirmed, serious incidents end to end | The emergency response team |

My work spans triage, investigation, and detection engineering.

---

## My Day to Day

This is what my work at Voya Financial involves.

| Activity | What it involves | Scale |
| :--- | :--- | :--- |
| **Alert triage and investigation** | Working the alert queue in Splunk and CrowdStrike, deciding what is real, and investigating across cloud, endpoint, and enterprise systems | 45+ alerts and incidents per week |
| **Detection tuning** | Rewriting rules that fire too often on harmless activity, so real attacks stand out | 100+ detections built and tuned, 35% fewer false alarms |
| **Automation** | Writing Python that does the repetitive lookup work an analyst would do by hand | Investigations cut from 15 minutes to 15 seconds |
| **Threat hunting** | Searching endpoint, network, and identity data for attacker behavior no alert has flagged | Findings become new detections |
| **Playbooks and teamwork** | Writing step-by-step response guides with engineering and infrastructure teams | Response time (MTTR) down 45% |

Before Voya, at RTCS, I monitored firewalls, email security, and data loss prevention systems, triaged 100+ alerts a week, and led containment on 3 to 5 escalated incidents per week.

---

## How Success Is Measured

| Measure | Plain meaning | Why it matters |
| :--- | :--- | :--- |
| **MTTD** (mean time to detect) | How long an attacker is inside before we notice | Less time inside means less damage |
| **MTTR** (mean time to respond) | How long from noticing to containing | Faster containment stops the spread |
| **False positive rate** | How often an alarm fires on something harmless | Too many false alarms bury the real ones |
| **Coverage** | How many known attack techniques we can detect | Gaps are where attackers get through. See my [ATT&CK Coverage Map](attack-coverage.md) |

---

## How the Labs Prove This

Each lab in this portfolio is one slice of the work above, documented the way I would in a real ticket:

| Lab | Part of the job it shows |
| :--- | :--- |
| [01 Process Auditing](../investigations/lab-01-windows-process.md) | Setting up the logging that every investigation depends on |
| [02 Network Traffic](../investigations/lab-02-network-traffic.md) | Investigating with network recordings when computer logs are missing |
| [03 LSASS Credential Dumping](../investigations/lab-03-splunk-lsass.md) | A full threat hunt: investigation, timeline, verdict, and a tested detection |
| [04 Phishing](../investigations/lab-04-phishing-analysis.md) | Triaging the most common attack: malicious email |
| [05 Brute Force](../investigations/lab-05-sentinel-bruteforce.md) | Writing and testing detection logic, and finding its blind spots |

New to the terms? The [Glossary](glossary.md) explains every one in plain English.

---

## Where I'm Growing

| Timeframe | Goal |
| :--- | :--- |
| **Now** | Finishing CompTIA Security+ and TryHackMe SAL1 |
| **Next labs** | Build an Active Directory home lab, rerun Lab 05 on real Microsoft Sentinel data, publish a Python IOC enrichment tool, and hunt command-and-control beacons in network data |
| **Skills I'm deepening** | Detection engineering (writing and testing rules across Splunk, Sentinel, and Sigma), cloud and identity security (Entra ID sign-in attacks), and incident response leadership |
| **Where that leads** | Senior SOC and incident response work, where I can own investigations end to end and build the detections the rest of the team relies on |
