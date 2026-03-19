# 🚨 Ransomware Incident Response Playbook

> **Classification:** TLP:WHITE — Public  
> **Version:** 1.0 | **Author:** Arash  
> **Last Updated:** 2025-01-01  
> **MITRE ATT&CK Version:** v14

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
3. [Phase 1: Detection & Identification](#phase-1-detection--identification)
4. [Phase 2: Containment](#phase-2-containment)
5. [Phase 3: Eradication](#phase-3-eradication)
6. [Phase 4: Recovery](#phase-4-recovery)
7. [Phase 5: Post-Incident Activity](#phase-5-post-incident-activity)
8. [IOC Collection Template](#ioc-collection-template)
9. [Communication Templates](#communication-templates)

---

## Overview

This playbook provides a structured response procedure for ransomware incidents.  
It maps to the **NIST SP 800-61r2** incident response lifecycle and **MITRE ATT&CK** framework.

### Severity Classification

| Severity | Criteria | SLA |
|---|---|---|
| 🔴 **P1 - Critical** | Production systems encrypted, business halted | 15 min response |
| 🟠 **P2 - High** | Partial encryption, spread ongoing | 1 hour response |
| 🟡 **P3 - Medium** | Isolated system, no spread detected | 4 hours response |
| 🟢 **P4 - Low** | Suspected/blocked, no encryption confirmed | 24 hours response |

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Phishing | T1566 | Malicious email attachment/link |
| Initial Access | Valid Accounts | T1078 | Stolen credentials via infostealer |
| Execution | User Execution | T1204 | User opens malicious attachment |
| Execution | PowerShell | T1059.001 | Payload delivery via PowerShell |
| Persistence | Scheduled Task | T1053.005 | Ransom note dropped at startup |
| Defense Evasion | Obfuscated Files | T1027 | Encoded payload to bypass AV |
| Credential Access | OS Credential Dumping | T1003 | LSASS dump for lateral movement |
| Discovery | Network Share Discovery | T1135 | Enumerating shares to encrypt |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | Spread via SMB shares |
| Impact | Data Encrypted for Impact | T1486 | File encryption — core ransomware action |
| Impact | Inhibit System Recovery | T1490 | Shadow copy deletion |
| Impact | Data Exfiltration | T1041 | Double extortion — data stolen before encryption |

---

## Phase 1: Detection & Identification

### 🔍 Initial Detection Checklist

- [ ] Confirm alert source (EDR / SIEM / user report)
- [ ] Identify affected system(s) — hostname, IP, user
- [ ] Determine if encryption is **in progress** or **completed**
- [ ] Check for ransom note (`.txt` / `.html` dropped in directories)
- [ ] Identify ransomware family if possible (note file extension, ransom note style)

### Detection Queries (Splunk)

```spl
# Rapid file creation/modification (encryption indicator)
index=wineventlog EventCode=4663 ObjectType=File
| stats count by SubjectUserName, ObjectName, _time
| where count > 100

# Shadow copy deletion (T1490)
index=wineventlog EventCode=4688
| where CommandLine like "%vssadmin%delete%" OR CommandLine like "%wmic%shadowcopy%delete%"

# Ransom note dropped
index=wineventlog EventCode=4663
| where ObjectName like "%.txt%" OR ObjectName like "%.html%"
| where ObjectName like "%READ_ME%" OR ObjectName like "%DECRYPT%" OR ObjectName like "%RESTORE%"
```

### Initial Questions to Answer

1. What is the **patient zero** (first infected machine)?
2. Is the ransomware **still running** on any system?
3. Are **backups** intact and offline?
4. Has **data exfiltration** occurred (check outbound traffic)?
5. Are **domain controllers** affected?

---

## Phase 2: Containment

### ⚡ Immediate Actions (First 15 Minutes)

> ⚠️ **Do NOT power off infected machines without forensic consideration** — RAM may contain encryption keys.

```bash
# 1. ISOLATE affected hosts at network level
# EDR: Isolate host (CrowdStrike/SentinelOne/Defender)
# Firewall: Block host IP immediately

# 2. Disable compromised accounts
net user <username> /active:no          # Windows
passwd -l <username>                    # Linux

# 3. Revoke Active Directory credentials if domain-joined
Disable-ADAccount -Identity <username>

# 4. Block lateral movement
# Block SMB (445) between segments at firewall
# Disable admin shares if possible
```

### Containment Decision Tree

```
Is encryption still in progress?
├── YES → Isolate immediately (network + host)
│         Take memory dump first if possible
│
└── NO  → Is ransomware still present on disk?
          ├── YES → Isolate, do NOT execute
          └── NO  → Proceed to evidence collection
```

### Evidence Collection

```bash
# Memory dump (Windows - before isolation if possible)
winpmem_mini_x64.exe memory.dmp

# Running processes
tasklist /v > processes.txt
Get-Process | Export-Csv processes.csv

# Network connections
netstat -anob > netstat.txt

# Recently modified files
Get-ChildItem -Recurse -File | Sort LastWriteTime -Descending | Select -First 100

# Prefetch / execution artifacts
Copy-Item C:\Windows\Prefetch\*.pf .\evidence\

# Event logs
wevtutil epl Security security.evtx
wevtutil epl System system.evtx
wevtutil epl Application application.evtx
```

---

## Phase 3: Eradication

### 🧹 Ransomware Removal Steps

1. **Identify malware artifacts**
   - Run EDR scan on isolated machine
   - Check startup locations: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   - Check scheduled tasks: `schtasks /query /fo LIST /v`
   - Check services: `Get-Service | Where-Object {$_.Status -eq "Running"}`

2. **Remove persistence mechanisms**
   ```powershell
   # Remove malicious scheduled tasks
   Unregister-ScheduledTask -TaskName "<malicious_task>" -Confirm:$false
   
   # Remove registry run keys
   Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<malicious_key>"
   ```

3. **Patch initial access vector**
   - Phishing: Block sender domain, hunt for similar emails
   - Vulnerable service: Apply patch or WAF rule
   - Stolen credentials: Force password reset for all users

4. **Check for backdoors**
   - New local administrator accounts
   - New scheduled tasks
   - New services installed
   - Web shells (if web server affected)

---

## Phase 4: Recovery

### 🔄 Recovery Decision

```
Are clean backups available?
├── YES → Restore from last known good backup
│         Verify backup integrity before restore
│         Restore to clean OS, NOT infected machine
│
└── NO  → Check for decryption options:
          1. Ransomware ID: https://id-ransomware.malwarehunterteam.com/
          2. Free decryptors: https://www.nomoreransom.org/
          3. Law enforcement contact (if critical)
          4. Last resort: negotiate (legal/management decision)
```

### Restoration Checklist

- [ ] Verify backup is **not infected** (scan before restore)
- [ ] Restore to **clean hardware or clean OS image**
- [ ] Apply all **security patches** before reconnecting
- [ ] Reset **all passwords** (especially admin/service accounts)
- [ ] Re-enable **MFA** on all accounts
- [ ] Verify **EDR agent** is installed and active
- [ ] Conduct **threat hunt** before declaring systems clean

---

## Phase 5: Post-Incident Activity

### 📊 Lessons Learned (within 2 weeks)

- [ ] Root cause analysis documented
- [ ] Timeline of attack reconstructed
- [ ] Security gaps identified
- [ ] Detection rules updated/created
- [ ] Playbook updated with new findings
- [ ] Management report prepared

### Metrics to Report

| Metric | Value |
|---|---|
| Time to Detect (TTD) | |
| Time to Contain (TTC) | |
| Systems Affected | |
| Data Encrypted (GB) | |
| Data Exfiltrated | Yes / No |
| Recovery Time (RTO) | |
| Estimated Cost | |

---

## IOC Collection Template

```yaml
incident_id: INC-YYYY-MM-DD-001
date: YYYY-MM-DD
analyst: 
ransomware_family: 

indicators_of_compromise:
  hashes:
    - type: SHA256
      value: 
      filename: 
      
  ips:
    - ip: 
      role: C2 / Exfil / Scanning
      country: 
      
  domains:
    - domain: 
      role: C2 / Payment portal
      
  files:
    - path: 
      description: Ransomware binary / dropper / ransom note
      
  registry:
    - key: 
      value: 
      
  mutex:
    - name: 

ransom_note_filename: 
encrypted_extension: 
payment_address: 
mitre_techniques:
  - T1566.001
  - T1059.001
  - T1486
  - T1490
```

---

## Communication Templates

### Initial Notification to Management

> **[SECURITY INCIDENT — P1]**  
> At [TIME], our security team detected a ransomware infection on [SYSTEM/DEPARTMENT].  
> Affected systems have been isolated. We are actively containing the incident.  
> Current status: [CONTAINED / INVESTIGATING / RECOVERING]  
> Next update: [TIME]

### User Communication

> Dear [DEPARTMENT] Team,  
> Due to an ongoing security incident, access to [SYSTEM] has been temporarily suspended.  
> Please do NOT power off your computers and report any unusual behavior to the IT Security team immediately.  
> Contact: [EMAIL / PHONE]

---

## 📚 References

- [NIST SP 800-61r2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Ransomware Techniques](https://attack.mitre.org/techniques/T1486/)
- [No More Ransom — Free Decryptors](https://www.nomoreransom.org/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
