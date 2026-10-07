# SOC Analyst Playbooks

[![CompTIA Security+](https://img.shields.io/badge/CompTIA-Security%2B%20Certified-E31937?style=flat-square)](https://www.credly.com/badges/7a0e6cea-24ce-4b7d-90bd-537cf50983b0)
![MITRE ATT&CK](https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-00C896?style=flat-square)
![Splunk SPL](https://img.shields.io/badge/queries-Splunk%20SPL-000000?style=flat-square)

The triage playbooks I work from as a SOC / Security Analyst: how I decide whether an alert is real, what evidence I collect, and when I escalate.

> **All content here is generic and synthetic.** No employer, client, or patient data, and no real hostnames, IPs, or addresses. Field names and sourcetypes are placeholders you adapt to your own environment.

## Playbooks

| # | Playbook | Focus | ATT&CK |
|---|----------|-------|--------|
| 01 | [Suspicious authentication](playbooks/01-suspicious-authentication.md) | Spraying, brute force, impossible travel, MFA fatigue | T1110, T1078, T1621 |
| 02 | [Vulnerability prioritization](playbooks/02-vulnerability-prioritization.md) | Turning Nessus / OpenVAS output into a fix order | n/a |
| 03 | [IDS/IPS alert validation](playbooks/03-ids-alert-validation.md) | Confirming a signature hit at packet level (Wireshark, Nmap) | T1046, T1071 |
| 04 | [Malware & ransomware triage](playbooks/04-malware-ransomware-triage.md) | Infection chain, isolation, recovery decisions | T1204, T1486, T1490 |
| 05 | [EDR alert triage](playbooks/05-edr-alert-triage.md) | Five-question method, benign vs malicious signals | by detection |
| 06 | [Lateral movement & privilege escalation](playbooks/06-lateral-movement-privilege-escalation.md) | Windows event IDs, hop mapping, credential theft | T1021, T1003, T1068 |
| 07 | [Data exfiltration](playbooks/07-data-exfiltration.md) | Baselines, staging, destinations, regulated data | T1041, T1048, T1567 |
| 08 | [Cloud identity anomaly](playbooks/08-cloud-identity-anomaly.md) | AWS / Azure / GCP audit logs, keys, logging tampering | T1078.004, T1098, T1562.008 |
| 09 | [Web attack triage](playbooks/09-web-attack-triage.md) | Did the attack work? Web shell hunt | T1190, T1595, T1505.003 |

Every playbook has the same shape: trigger, triage questions, decision table, containment, false positives, documentation, and a short synthetic worked example.

## Reference

- [Severity & escalation matrix](reference/severity-and-escalation.md): levels, modifiers, who to escalate to, and a handoff note template
- [Alert triage checklist](reference/alert-triage-checklist.md): the one-page routine for every alert
- [Log source cheat sheet](reference/log-source-cheatsheet.md): which log answers which question

## Detections

[`detections/additional-detections.md`](detections/additional-detections.md): Splunk SPL for suspicious inbox rules (BEC) and rare processes from user-writable paths, each with false-positive notes.

## Related repos

| Repo | What it covers |
|------|----------------|
| [phishing-analysis-playbook](https://github.com/Fahad-Quadri/phishing-analysis-playbook) | Phishing & BEC investigation, header analysis, incident report template |
| [splunk-detection-library](https://github.com/Fahad-Quadri/splunk-detection-library) | Eight ATT&CK-mapped SPL detections with tuning notes |
| [ioc-extractor](https://github.com/Fahad-Quadri/ioc-extractor) | Python CLI that extracts and defangs IOCs |
| [Home-lab-network-security](https://github.com/Fahad-Quadri/Home-lab-network-security) | pfSense, Kali, Suricata, and Active Directory lab |

## How I triage

1. **Scope:** what fired, on which asset or identity, and when?
2. **Enrich:** reputation, asset criticality, user context, prior alerts.
3. **Validate:** can I confirm it with a second data source?
4. **Decide:** false positive, benign true positive, or confirmed. Escalate with evidence attached.
5. **Document:** a record that another analyst or an auditor can follow without asking me.

## About

Syed Fahad Quadri, SOC / Security Analyst, Kansas City, MO.
[Portfolio](https://fahad-quadri.github.io/) · [LinkedIn](https://www.linkedin.com/in/syed-fahad-quadri-8a796a3a8/)
