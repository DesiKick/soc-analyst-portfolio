---
title: Event ID Reference
---

# Windows and Sysmon Event ID Reference

The events I rely on most in investigations, and what each one tells me.

---

## Windows Security Log: Logons and Accounts

| Event ID | What it records | What I look for |
| :--- | :--- | :--- |
| **4624** | Successful logon | Logon type, source IP, and whether it follows a run of failures |
| **4625** | Failed logon | SubStatus (why it failed), source IP, volume over time |
| **4634 / 4647** | Logoff | Session length when building a timeline |
| **4648** | Logon with explicit credentials | `runas` or a tool using alternate credentials, often lateral movement |
| **4672** | Special privileges assigned at logon | An admin-level logon; unusual for that user is a red flag |
| **4720** | User account created | New accounts outside the normal provisioning process |
| **4724** | Password reset attempt | Reset by someone other than the user or helpdesk |
| **4728 / 4732 / 4756** | Member added to a global / local / universal security group | Anyone added to Domain Admins or local Administrators |
| **4740** | Account locked out | Brute force against one account, and the source machine name |
| **1102** | Security log cleared | Almost always worth an immediate look |

## Windows Security Log: Execution and Persistence

| Event ID | What it records | What I look for |
| :--- | :--- | :--- |
| **4688** | New process created | Parent-child lineage and the command line, if enabled |
| **4697** | Service installed (Security log) | Services running from user-writable paths |
| **4698** | Scheduled task created | Tasks that run scripts or binaries from Temp or AppData |
| **7045** | Service installed (System log) | Same as 4697; present even when 4697 auditing is off |
| **4104** | PowerShell script block logged (PowerShell Operational log) | The decoded script content, even if it was obfuscated |

## Domain Controller: Kerberos and NTLM

| Event ID | What it records | What I look for |
| :--- | :--- | :--- |
| **4768** | Kerberos TGT requested | Requests for accounts without pre-authentication (AS-REP roasting) |
| **4769** | Kerberos service ticket requested | Many requests with RC4 encryption (`0x17`) from one user: Kerberoasting |
| **4771** | Kerberos pre-authentication failed | Failure code `0x18` is a bad password; high volume is guessing or spraying |
| **4776** | NTLM credential validation | Failures across many accounts from one workstation |

---

## Logon Types (4624 / 4625)

| Type | Name | Typical source |
| :--- | :--- | :--- |
| **2** | Interactive | At the keyboard or console |
| **3** | Network | SMB file shares, most remote tooling, also brute force over SMB |
| **4** | Batch | Scheduled tasks |
| **5** | Service | A service starting under an account |
| **7** | Unlock | Workstation unlock |
| **8** | NetworkCleartext | Credentials sent in cleartext, for example basic authentication |
| **9** | NewCredentials | `runas /netonly`; also used by some credential theft tools |
| **10** | RemoteInteractive | RDP |
| **11** | CachedInteractive | Logon with cached domain credentials, off network |

---

## 4625 Failure Codes (SubStatus)

| Code | Meaning | What it suggests |
| :--- | :--- | :--- |
| `0xC000006A` | Wrong password for a real account | Password guessing |
| `0xC0000064` | Account does not exist | Username enumeration or spraying guessed names |
| `0xC0000072` | Account disabled | Attempts on dormant accounts |
| `0xC0000234` | Account locked out | Lockout triggered |
| `0xC0000071` | Password expired | Often a stale service account, not an attack |
| `0xC0000193` | Account expired | Contractor or temporary account still in use somewhere |
| `0xC000006F` | Logon outside allowed hours | Policy violation or stolen credentials used off hours |
| `0xC0000070` | Logon from an unauthorized workstation | Credentials used from the wrong machine |

---

## Sysmon

| Event ID | What it records | What I look for |
| :--- | :--- | :--- |
| **1** | Process creation, with hashes and parent command line | The richer version of 4688 |
| **3** | Network connection | Processes that should not talk to the internet, like `rundll32` or Office |
| **7** | Image (DLL) loaded | Unsigned DLLs loaded into trusted processes |
| **8** | CreateRemoteThread | Code injection into another process |
| **10** | Process access | Anything opening `lsass.exe` with memory-read rights (`0x1010`, `0x1410`, `0x1fffff`). See [Lab 03](../investigations/lab-03-splunk-lsass.md) |
| **11** | File created | Dump files, dropped executables, files in startup folders |
| **12 / 13 / 14** | Registry key and value changes | Run keys and other persistence locations |
| **22** | DNS query | The process behind a suspicious domain lookup |
| **23** | File deleted (archived) | Attackers cleaning up after themselves |
