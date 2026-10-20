---
title: How I Triage an Alert
---

# How I Triage an Alert

The method I use when an alert lands in the queue, from first look to close or escalate.

---

## 1. The First Five Questions

Before touching a query, I answer these from the alert itself:

1. **What fired, and what is it designed to catch?** Read the rule logic, not just the title.
2. **Who and what is involved?** User, host, source and destination IPs, process.
3. **Is this normal for them?** Has this user, host, or process done this before? Check a 7 to 30 day baseline.
4. **What happened right before and right after?** Pull a time window of 15 minutes either side on the same host and user.
5. **If this is real, what is the impact?** A domain controller or a finance user changes the urgency.

---

## 2. Verdicts

| Verdict | Meaning | Example |
| :--- | :--- | :--- |
| **True positive** | Malicious activity the rule was built to catch | `procdump -ma lsass.exe` from a Temp folder |
| **Benign true positive** | The rule worked correctly, but the activity is authorized | IT admin creates an LSASS dump during a sanctioned troubleshooting ticket |
| **False positive** | The rule fired on activity it should not match | An EDR agent's normal LSASS access matching a too-broad rule |

A false positive is a **rule problem**: I tune it. A benign true positive is a **context problem**: I document it and consider an allowlist with an owner and an expiry date.

---

## 3. Severity

| | **Low impact** (single workstation, standard user) | **High impact** (server, DC, privileged account, sensitive data) |
| :--- | :--- | :--- |
| **High confidence** | Medium | **Critical** |
| **Low confidence** | Low | High |

Severity goes up immediately for any of: a successful logon after a brute force, credential access tools, activity on a domain controller, or signs of data leaving the network.

---

## 4. When I Escalate

I escalate to incident response when any of these are true:

- Confirmed credential theft or a guessed password that worked
- Malicious code ran, not just arrived
- The same indicator appears on more than one host
- A privileged account or domain controller is involved
- I cannot rule out malicious activity within the triage time limit

---

## 5. Sample Ticket

Written for the activity in [Lab 03](../investigations/lab-03-splunk-lsass.md), the way I would hand it to IR:

!!! danger "INC-LAB03: LSASS memory dumped on two domain controllers"

    **Verdict:** True positive | **Severity:** Critical | **Status:** Escalated to IR

    **Summary:** Multiple tools opened `lsass.exe` with full access (`0x1fffff`) and wrote memory dumps to disk on `win-dc-807` and `win-dc-262`. Mimikatz then parsed a dump offline. Domain credentials should be treated as compromised.

    **Timeline (UTC, win-dc-807, 2020-11-03):**

    - 15:52:58: Temp binary dropped by `wce.exe`, run as a SYSTEM service, opens LSASS 38 times
    - 15:52:59: `procdump -ma lsass.exe` writes `lsass_dump.dmp`
    - 15:53:03: `rundll32 comsvcs.dll MiniDump` and `Outflank-Dumpert.exe` write dumps
    - 15:53:03: `mimikatz sekurlsa::minidump` parses a dump
    - 15:53:06: Dump files deleted

    **Indicators:** SHA256 `7234C8F9...147D14C3`, `C:\AtomicRedTeam\atomics\T1003.001\bin\`, `*lsass*.dmp`

    **Actions requested:** isolate both DCs, reset privileged credentials, reset `krbtgt` twice, hunt the hash fleet-wide.

    **Detection coverage:** live LSASS access is caught by the Lab 03 rule. Offline Mimikatz parsing is not, because it only shows up in process creation logs. Recommend a command line rule for `sekurlsa`.
