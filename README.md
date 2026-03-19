# 📖 Ransomware Incident Response Playbook

> A complete, production-ready IR playbook for ransomware incidents. Includes MITRE ATT&CK mapping, Splunk detection queries, containment procedures, and communication templates.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red) ![NIST](https://img.shields.io/badge/NIST-SP_800--61r2-blue) ![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Playbook Covers

| Phase | Actions |
|---|---|
| 🔍 Detection | Splunk queries, IOC identification, patient zero |
| ⚡ Containment | Network isolation, account lockdown, evidence collection |
| 🧹 Eradication | Malware removal, persistence cleanup, patching |
| 🔄 Recovery | Backup restoration, system validation, reconnection |
| 📊 Post-Incident | Timeline reconstruction, lessons learned, metrics |

## 🗺️ MITRE ATT&CK Coverage

T1566 · T1078 · T1059.001 · T1486 · T1490 · T1110 · T1003 · T1021.002

## 📄 Contents

- [PLAYBOOK.md](./PLAYBOOK.md) — Full incident response playbook
- Splunk detection queries included
- IOC collection template
- Management & user communication templates

## 🔗 Related Projects

- [sigma-siem-rules](https://github.com/pentest2/sigma-siem-rules) — Detection rules for early ransomware detection
