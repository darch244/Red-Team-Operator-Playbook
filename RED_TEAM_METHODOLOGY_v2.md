# Red Team Operator Methodology
## A Structured Reference for Adversary Emulation Engagements

**Author:** Mostafa Ibrahim (DarcHacker)
**Version:** 2.0
**Last Updated:** July 2026
**Scope of this document:** Methodology, decision-making, OPSEC principles, detection correlation, and reporting standards for authorized red team engagements. This is a *process and knowledge reference*, not an operational toolkit — it intentionally does not include ready-to-execute exploit payloads, credential-harvesting configurations, or C2 infrastructure profiles.

---

## Table of Contents

1. [Purpose & Scope of This Document](#1-purpose--scope-of-this-document)
2. [Pre-Engagement & Scoping](#2-pre-engagement--scoping)
3. [Reconnaissance Methodology](#3-reconnaissance-methodology)
4. [Initial Access — Decision Framework](#4-initial-access--decision-framework)
5. [Post-Exploitation Methodology](#5-post-exploitation-methodology)
6. [Privilege Escalation — Methodology](#6-privilege-escalation--methodology)
7. [Persistence — Methodology & OPSEC Tiers](#7-persistence--methodology--opsec-tiers)
8. [Active Directory Attack Paths — Conceptual Map](#8-active-directory-attack-paths--conceptual-map)
9. [Lateral Movement — Methodology](#9-lateral-movement--methodology)
10. [OPSEC & Evasion Principles](#10-opsec--evasion-principles)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [Detection & Purple Team Correlation](#12-detection--purple-team-correlation)
13. [Reporting Framework](#13-reporting-framework)
14. [Evidence Collection Standards](#14-evidence-collection-standards)
15. [References](#15-references)
16. [Glossary](#16-glossary)

---

## 1. Purpose & Scope of This Document

This methodology exists to demonstrate **how a red team operator thinks and decides**, not to serve as a step-by-step attack script. It is built around five principles:

1. **Methodology over tools** — tools change; the decision process doesn't.
2. **OPSEC first** — every action is evaluated for detection risk before execution.
3. **Documentation is the deliverable** — if it isn't recorded, it didn't happen for the client.
4. **Every offensive technique maps to a defensive one** — attack knowledge is only complete when paired with detection knowledge.
5. **Authorization is absolute** — nothing in this document is intended for use outside a signed Rules of Engagement (RoE).

This document deliberately omits exact exploit commands, malicious infrastructure configurations, and credential-theft tooling syntax. Those specifics belong in a private, access-controlled operator runbook — not in a portfolio document. What's captured here is the *decision layer* above that: what to check, in what order, what it means when you find it, and how to report it.

---

## 2. Pre-Engagement & Scoping

### 2.1 Required Documents Before Any Testing Begins

| Document | Purpose |
|---|---|
| Rules of Engagement (RoE) | Defines in-scope/out-of-scope assets, testing windows, escalation contacts, legal authorization |
| Scope Definition | Network architecture, testing methodology (external-only, assumed breach, full chain), tools permitted |
| Business Impact Assessment | Critical systems that must remain online, change-management constraints |
| Infrastructure Access Details | VPN/jump host access, any pre-provided credentials, baseline security tooling in place |

### 2.2 Scoping Checklist

```
□ Networks and domains explicitly in scope (with written confirmation)
□ Off-limits systems clearly identified (prod DBs, backups, third-party SaaS)
□ Authorization level defined: unauthenticated / low-priv credentials / assumed breach
□ Social engineering & phishing explicitly authorized or excluded
□ Destructive testing explicitly excluded unless separately authorized
□ Emergency contact and stop-work procedure confirmed
□ Data handling and retention terms agreed (especially for exfiltrated sample data)
```

### 2.3 Engagement Infrastructure Principles

- Never operate C2 or phishing infrastructure that directly exposes the operator's real IP to the target.
- Use redirectors/proxies between the target and the team server, and rotate domains/certificates per engagement.
- Maintain a clean separation between attack infrastructure and any personal or previously-used infrastructure to avoid attribution bleed-through between engagements.
- Log everything on the operator side independently of the client's logs — this is your evidentiary backup.

---

## 3. Reconnaissance Methodology

### 3.1 Objective

Build a target profile — attack surface, technology stack, employee footprint, and likely weak points — **without generating alerts**, before any active testing window opens.

### 3.2 Reconnaissance Categories

| Category | What You're Building |
|---|---|
| Domain & registration research | Ownership, related domains, hosting providers |
| DNS enumeration (passive) | Subdomains, mail infrastructure, TXT/SPF records revealing tooling |
| Certificate transparency review | Internal hostnames leaked via SAN entries |
| Technology fingerprinting | Web server, framework, CDN, CMS — narrows exploit research |
| Employee & email harvesting | Naming convention, org structure, likely phishing targets |
| Exposed storage / repos | Public S3 buckets, misconfigured shares, leaked credentials in code repos |

### 3.3 Decision Tree — Handling What You Find During Recon

```
IF you find exposed data (S3 bucket, open share, public repo secrets):
├─ Record location, contents summary, and timestamp for the report
├─ Do NOT modify, delete, or exfiltrate beyond what's needed to prove impact
└─ Flag for immediate informal notification if actively exploitable by third parties

IF you find employee credentials in breach dumps or public sources:
├─ Note them for later authorized credential-validation testing only
└─ Do NOT use them until the active testing phase and RoE explicitly permit it

IF you find a service with default/vendor credentials:
├─ Note the finding
└─ Attempt use only within the authorized exploitation phase, not during OSINT
```

### 3.4 Recon OPSEC Notes

- Passive-only techniques (WHOIS, DNS, CT logs, search engines) generate no traffic to the target and carry no detection risk.
- Any direct interaction with target infrastructure (port scans, banner grabs) should be scheduled and paced according to the RoE's testing window and throttling requirements.

---

## 4. Initial Access — Decision Framework

### 4.1 Common Initial Access Vectors (by category)

| Vector Category | MITRE Technique | Typical Precondition |
|---|---|---|
| Phishing (credential harvesting) | T1566.002 | Valid email addresses, plausible pretext |
| Phishing (malicious attachment/macro) | T1566.001 | Office macros enabled, weak email filtering |
| Exploiting public-facing application | T1190 | Known unpatched vuln on internet-facing service |
| Valid accounts (leaked/reused credentials) | T1078 | Credential reuse across breaches |
| External remote services (VPN, RDP) | T1133 | Weak MFA / exposed remote access |

### 4.2 Choosing a Vector — Decision Logic

```
IF RoE authorizes phishing:
├─ Prioritize pretexts relevant to the organization (HR, IT, finance cycles)
├─ Prefer credential-harvesting or macro delivery based on client's email filtering maturity
└─ Track click-rate and compromise-rate as reportable metrics

IF RoE excludes phishing (technical-only assessment):
├─ Focus on public-facing application testing (T1190)
└─ Focus on external service misconfiguration (T1133)

IF assumed-breach engagement (starting with a foothold or credentials):
└─ Skip to Section 5 — Post-Exploitation
```

### 4.3 Initial Access Validation Checklist

```
□ Confirm interactive or command execution access on the target host
□ Record: hostname, username, process context, source IP, timestamp
□ Perform an immediate baseline check of defensive posture (AV/EDR presence,
  logging status) BEFORE further action — this determines your OPSEC budget
□ Document the delivery method and any user interaction required (for the report's
  human-risk findings, e.g., click rates, MFA fatigue)
```

---

## 5. Post-Exploitation Methodology

### 5.1 The First Five Checks After Any Foothold

Before taking any further action, establish situational awareness. Order matters — each check informs whether the next step is safe:

1. **Current privilege level** — determines whether you need local privilege escalation before doing anything sensitive.
2. **EDR/AV presence and mode** — determines your OPSEC budget for the rest of the operation.
3. **Network context** — local subnet, DNS servers, indications of domain membership.
4. **Domain membership confirmation** — confirms whether you're in a workgroup or AD environment, which branches the whole methodology.
5. **Patch/build baseline** — informs which privilege escalation and lateral movement techniques are even relevant.

### 5.2 Network & Host Enumeration Objectives

| Objective | What You're Looking For |
|---|---|
| Host discovery | Other reachable systems, especially domain controllers, file servers, DB servers |
| Active connections | Existing trust relationships and administrative sessions in progress |
| Routing table | Additional network segments reachable via VPN/multi-homed hosts |
| Local credential artifacts | Cached credentials, saved sessions — noted, not necessarily extracted, depending on RoE and stealth requirements |

### 5.3 Decision Tree — Escalation Path Selection

```
Check current privilege level:
├─ Already SYSTEM/root
│  └─ Proceed to Lateral Movement (Section 9)
│
├─ High integrity, not SYSTEM
│  ├─ Evaluate locally exploitable privilege primitives
│  │  (impersonation privileges, misconfigured services)
│  └─ Proceed to Privilege Escalation (Section 6)
│
└─ Standard/medium-integrity user
   ├─ Check patch level for known local vulnerabilities
   ├─ Check for UAC bypass conditions
   └─ Proceed to Privilege Escalation (Section 6)
```

---

## 6. Privilege Escalation — Methodology

### 6.1 Categories of Windows Privilege Escalation

| Category | MITRE Technique | Indicator to Check For |
|---|---|---|
| Unquoted service paths | T1574.009 | Service binary path contains spaces and no quotes |
| Weak service/file permissions | T1574.010 | Writable service binaries or configs by low-priv users |
| Token impersonation abuse | T1134 | `SeImpersonatePrivilege` / `SeDebugPrivilege` enabled |
| AlwaysInstallElevated misconfiguration | T1548.002 | Registry keys enabling elevated MSI installs |
| Unpatched kernel vulnerabilities | T1068 | Missing security updates matching known local exploits |

### 6.2 Categories of Linux Privilege Escalation

| Category | MITRE Technique | Indicator to Check For |
|---|---|---|
| Sudo misconfiguration | T1548.003 | `sudo -l` reveals NOPASSWD entries on exploitable binaries |
| SUID/SGID binaries | T1548.001 | Non-standard binaries with SUID bit set |
| Kernel exploits | T1068 | Kernel version matching known local privilege escalation CVEs |
| Writable cron jobs / systemd units | T1053 | Scheduled tasks writable by unprivileged users |

### 6.3 Privilege Escalation Decision Logic

```
IF a locally exploitable misconfiguration is found:
├─ Prefer it over a kernel exploit — lower crash risk, better OPSEC
└─ Document exact misconfiguration for the report (this is often a HIGH finding on its own)

IF no misconfiguration exists and only a kernel exploit path is available:
├─ Weigh stability risk against RoE constraints on system availability
└─ Confirm with engagement lead before use if system is business-critical

ALWAYS:
└─ Re-run the "first five checks" (Section 5.1) after every successful escalation
```

---

## 7. Persistence — Methodology & OPSEC Tiers

Persistence should be selected based on required dwell time and acceptable detection risk — not by default. Every mechanism trades stealth against resilience.

| Tier | Mechanism Category | MITRE Technique | Detection Risk |
|---|---|---|---|
| Low risk | User-context registry run keys | T1547.001 | Low — blends with legitimate autostart entries if named carefully |
| Medium risk | Scheduled tasks | T1053.005 | Medium — visible to `autoruns`-style audits |
| Higher risk | WMI event subscriptions | T1546.003 | Higher — abnormal in most environments, strong EDR signature coverage |
| Higher risk | Service creation | T1543.003 | Higher — new service creation is commonly alerted on |

### 7.1 Decision Logic

```
IF engagement objective is short-duration (days):
└─ Prefer low-risk, user-context persistence; avoid SYSTEM-level artifacts

IF engagement objective requires long-duration access (weeks) and detection
testing is explicitly in scope:
└─ Layer multiple tiers to test the client's detection coverage across categories

ALWAYS:
└─ Maintain a persistence inventory (what, where, when installed) for guaranteed
   cleanup at engagement end — an un-removed backdoor is a critical incident.
```

---

## 8. Active Directory Attack Paths — Conceptual Map

This section maps *what* AD attack classes exist and *why they work*, without exact exploitation syntax. Pair each with Section 11 (MITRE) and Section 12 (Detection) for the full picture.

| Attack Class | Root Cause | MITRE Technique |
|---|---|---|
| Kerberoasting | Service accounts with SPNs use weak/crackable passwords; any authenticated user can request a service ticket and attempt offline cracking | T1558.003 |
| AS-REP Roasting | Accounts with Kerberos pre-authentication disabled can have their hash requested without a password | T1558.004 |
| Unconstrained delegation abuse | Hosts trusted for unconstrained delegation cache TGTs of any user who authenticates to them | T1558 / T1550 |
| ACL/DACL abuse | Overly permissive object permissions (e.g., `GenericAll`, `WriteDACL`) allow privilege chains to Domain Admin | T1484.001 |
| Golden/Silver Ticket forgery | Compromise of the `krbtgt` (or service account) hash allows forging arbitrary Kerberos tickets | T1558.001 / T1558.002 |
| Pass-the-Hash / Pass-the-Ticket | NTLM hashes or Kerberos tickets are reusable without the plaintext password | T1550.002 / T1550.003 |
| Trust relationship abuse | Cross-domain/cross-forest trusts extend the attack surface beyond the initially compromised domain | T1482 |

### 8.1 Why Each Matters (Report Framing)

- **Kerberoasting / AS-REP Roasting** are almost always a *password policy* finding, not a "vulnerability" — remediation is managed service accounts + strong password policy, not a patch.
- **Unconstrained delegation** is an architecture finding — remediation is removing the delegation flag and moving to constrained/resource-based delegation.
- **ACL abuse** requires a full path graph (e.g., BloodHound-style analysis) to demonstrate — the finding is the *path*, not a single misconfigured object.
- **Golden Ticket** findings should be framed around the exposure that led to `krbtgt` compromise (usually a prior DC compromise), not treated in isolation.

### 8.2 Discovery-Level Decision Tree

```
IF Kerberoastable accounts exist:
├─ Note account name, SPN, and whether it's a high-privilege account
└─ Report as HIGH if account has elevated group membership, MEDIUM otherwise

IF unconstrained delegation is found on a reachable host:
├─ Note the host and what privileged accounts routinely authenticate to it
└─ Report as HIGH — this is a common real-world domain-admin path

IF ACL misconfigurations are found on privileged objects:
├─ Map the full path to Domain Admins (or equivalent) before reporting
└─ Report severity based on the shortest exploitable path length
```

---

## 9. Lateral Movement — Methodology

### 9.1 Movement Techniques by Category

| Category | MITRE Technique | Typical Use Case |
|---|---|---|
| Remote services (SMB/WinRM/RDP) | T1021 | Moving with valid credentials or tickets to a new host |
| Pass-the-Hash / Pass-the-Ticket | T1550 | Moving without needing the plaintext password |
| Remote service creation | T1569.002 | Executing code on a remote host via a service |
| Exploitation of remote services | T1210 | Moving via unpatched software rather than credentials |

### 9.2 Decision Logic

```
IF valid credentials or tickets for a target host are already available:
└─ Prefer built-in remote administration methods over exploitation (quieter, expected traffic pattern)

IF no credentials are available but an unpatched service exists on the target:
└─ Exploitation may be necessary — weigh stability risk and confirm scope coverage first

ALWAYS:
└─ Track every host touched, with timestamp and method, for the lateral movement
   timeline in the final report
```

---

## 10. OPSEC & Evasion Principles

These are principles, not techniques — the "how" varies by tooling and changes constantly; the "why" doesn't.

1. **Minimize footprint before maximizing access.** Every command run is a potential detection event; batch reconnaissance rather than probing repeatedly.
2. **Match traffic patterns to the environment.** Unusual protocols, off-hours activity, and abnormal data volumes are the most common detection triggers — not the tooling itself.
3. **Assume logging exists even when EDR doesn't.** Windows Event Logs, Sysmon, and network flow logs often persist even in under-monitored environments.
4. **Plan your cleanup before you need it.** Know exactly what artifacts (files, registry keys, scheduled tasks, services) you've created, so removal at engagement end is complete and verifiable.
5. **Never exceed the RoE's blast radius**, even if a technique would technically work on an out-of-scope system.
6. **Document detection events on the operator side.** If the blue team catches an action, that's a valuable data point for the report — not a failure to hide.

---

## 11. MITRE ATT&CK Mapping

A consolidated view of the techniques referenced throughout this methodology, useful for engagement-planning coverage checks and for report appendices.

| Phase | Technique ID | Technique Name |
|---|---|---|
| Reconnaissance | T1595 | Active Scanning |
| Reconnaissance | T1589 | Gather Victim Identity Information |
| Initial Access | T1566.001/.002 | Phishing (Attachment / Link) |
| Initial Access | T1190 | Exploit Public-Facing Application |
| Initial Access | T1133 | External Remote Services |
| Execution | T1059 | Command and Scripting Interpreter |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Persistence | T1053.005 | Scheduled Task |
| Persistence | T1546.003 | WMI Event Subscription |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Privilege Escalation | T1134 | Access Token Manipulation |
| Credential Access | T1558.001/.003/.004 | Kerberoasting / Golden Ticket / AS-REP Roasting |
| Credential Access | T1003 | OS Credential Dumping |
| Lateral Movement | T1021 | Remote Services |
| Lateral Movement | T1550 | Use Alternate Authentication Material |
| Discovery | T1482 | Domain Trust Discovery |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |

---

## 12. Detection & Purple Team Correlation

For every offensive technique above, the corresponding defensive question is: *what would this look like in the SOC?*

| Technique Category | Relevant Windows Event IDs | Detection Concept |
|---|---|---|
| Kerberoasting | 4769 (Kerberos Service Ticket Request) | Multiple RC4 ticket requests for the same account in a short window |
| AS-REP Roasting | 4768 (Kerberos TGT Request) | TGT requests for accounts with pre-auth disabled |
| Golden/Silver Ticket | 4624, 4672 | Logon anomalies — tickets with implausible lifetimes or inconsistent PAC data |
| Credential dumping (LSASS access) | 4656, 4663, Sysmon Event ID 10 | Unusual process handles opened to `lsass.exe` |
| Scheduled task persistence | 4698 (Task Created) | New scheduled tasks created outside change-management windows |
| New service creation | 7045 | Services installed by non-administrative context or with unsigned binaries |
| Lateral movement (PtH/PtT) | 4624 (Logon Type 3/9), 4648 | Logons using NTLM where Kerberos is expected, or explicit credential logons |
| WMI persistence | Sysmon Event ID 19-21 | WMI event consumer/filter creation |

### 12.1 Detection Engineering Resources to Reference in a Real Engagement

- **Sigma rules** — community-maintained, technique-mapped detection logic portable across SIEMs (Splunk, Elastic, Sentinel).
- **MITRE ATT&CK Navigator** — for visualizing detection coverage gaps discovered during the engagement.
- **Vendor-specific detection content** — Microsoft Defender for Identity analytics, Elastic Security detection rules, Splunk ES correlation searches — should be checked against what was and wasn't triggered during the assessment.

### 12.2 Purple Team Value Proposition

A red team finding is most valuable to a client when paired with: *"here's what we did, here's what should have alerted, and here's why it didn't."* This turns an offensive engagement into a direct improvement to detection engineering — which is the argument for including this section in any professional-facing version of a methodology document.

---

## 13. Reporting Framework

### 13.1 Severity Rating Guidance

| Severity | CVSS-like Range | Example |
|---|---|---|
| Critical | 9.0–10.0 | Unauthenticated RCE on internet-facing system; full domain compromise achievable remotely |
| High | 7.0–8.9 | Local privilege escalation to SYSTEM/root; Kerberoastable Domain Admin-equivalent account |
| Medium | 4.0–6.9 | Non-sensitive information disclosure; ACL misconfiguration on a low-value object |
| Low | 1.0–3.9 | Outdated software versions with no demonstrated exploit path; hardening recommendations |

### 13.2 Report Structure

```
Executive Summary
├─ Engagement overview (duration, scope, methodology used)
└─ Finding counts by severity

Methodology
└─ Phase-by-phase narrative of the approach taken

Detailed Findings
├─ Per finding: affected system, impact, evidence reference, remediation
└─ Ordered by severity

Evidence & Proof
├─ Screenshots and command output for each exploitation step
└─ Attack timeline with timestamps

Remediation Roadmap
├─ Immediate (24–48h)
├─ Short-term (1–2 weeks)
└─ Long-term (1–3 months)

Appendix
├─ MITRE ATT&CK technique mapping for the engagement
├─ Tools used (named, not with operational configuration)
└─ Detection coverage observations (Section 12 style)
```

### 13.3 Executive Summary Template

```
During a [N]-day engagement scoped as [assumed breach / external-only / full chain],
the assessment identified [N] Critical, [N] High, [N] Medium, and [N] Low findings.

Key attack path summary:
[Phase] → [Phase] → [Phase] → [Outcome]

Primary root causes:
1. [e.g., Password policy insufficient for service accounts]
2. [e.g., Missing MFA on privileged accounts]
3. [e.g., Delegation misconfiguration enabling privilege escalation]

Business impact: [data categories at risk, systems affected]

Top recommendations (ranked by impact):
1. ...
2. ...
3. ...
```

---

## 14. Evidence Collection Standards

For every material exploitation step, capture:

```
□ Command/action taken (described, not necessarily verbatim if sensitive)
□ Result/output demonstrating impact
□ Screenshot with visible timestamp
□ Timeline entry: [timestamp] → [action] → [outcome]
```

A consistent evidence trail is what separates a defensible professional report from an unverifiable claim — this matters as much for the client's trust as it does for any potential legal review of the engagement.

---

## 15. References

- MITRE ATT&CK — https://attack.mitre.org
- Microsoft Learn: Active Directory Security — https://learn.microsoft.com/security
- SpecterOps Blog (BloodHound, AD attack path research) — https://posts.specterops.io
- Harmj0y's Blog (AD tradecraft research) — https://harmj0y.medium.com
- Red Canary Threat Detection Reports — https://redcanary.com/blog
- Sigma Rules Project — https://github.com/SigmaHQ/sigma
- NIST SP 800-115: Technical Guide to Information Security Testing — https://csrc.nist.gov

---

## 16. Glossary

| Term | Definition |
|---|---|
| RoE | Rules of Engagement — the authorization document defining scope and limits |
| OPSEC | Operational security — practices minimizing detection risk during an operation |
| SPN | Service Principal Name — identifies a service instance to Kerberos |
| TGT / TGS | Ticket Granting Ticket / Ticket Granting Service ticket — Kerberos authentication artifacts |
| PAC | Privilege Attribute Certificate — embedded authorization data in Kerberos tickets |
| C2 | Command and Control — infrastructure used to manage compromised hosts |
| EDR | Endpoint Detection and Response |

---

## Closing Notes

**Core Principles:**
1. Methodology drives outcomes more reliably than any single tool.
2. OPSEC discipline is a professional obligation, not an optional extra.
3. If it isn't documented, it isn't part of the deliverable.
4. Every offensive finding should be paired with a detection recommendation.
5. Authorization scope is absolute — full stop.

---

**Author:** Mostafa Ibrahim (@DarcHacker)
**LinkedIn:** https://www.linkedin.com/in/mostafa-ibrahim-60b543341

*This document is intended as a professional methodology reference for authorized security engagements. It does not contain, and is not intended to serve as, executable attack tooling.*

END OF DOCUMENT
