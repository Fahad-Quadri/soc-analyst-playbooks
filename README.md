# SOC Analyst Playbooks & Splunk Detections

[![CompTIA Security+](https://img.shields.io/badge/CompTIA-Security%2B%20Certified-E31937?style=flat-square)](https://www.credly.com/badges/7a0e6cea-24ce-4b7d-90bd-537cf50983b0)
![MITRE ATT&CK](https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-00C896?style=flat-square)
![Splunk SPL](https://img.shields.io/badge/queries-Splunk%20SPL-000000?style=flat-square)

The triage playbooks and detection queries I work from as a SOC / Security Analyst: how I decide whether an alert is real, what evidence I collect, when I escalate, and how I document it.

> **All content here is generic and synthetic.** No employer, client, or patient data, and no real hostnames, IPs, or addresses. Field names and sourcetypes are placeholders you adapt to your own environment.

## Playbooks

| # | Playbook | Focus | ATT&CK |
|---|----------|-------|--------|
| 01 | [Phishing & BEC triage](playbooks/01-phishing-bec-triage.md) | Email evidence, header analysis, mailbox rule checks, escalation | T1566, T1114, T1534 |
| 02 | [Suspicious authentication](playbooks/02-suspicious-authentication.md) | Brute force, impossible travel, MFA fatigue | T1110, T1078, T1621 |
| 03 | [Vulnerability prioritization](playbooks/03-vulnerability-prioritization.md) | Turning Nessus / OpenVAS output into a fix order | n/a |
| 04 | [IDS/IPS alert validation](playbooks/04-ids-alert-validation.md) | Confirming a signature hit at packet level (Wireshark, Nmap) | T1046, T1071 |

## Detections

[`detections/splunk-spl.md`](detections/splunk-spl.md): commented SPL for failed-login bursts, impossible travel, suspicious inbox rules, rare process execution, and DNS anomalies, each with the false-positive cases to check.

## Templates

[`templates/incident-report.md`](templates/incident-report.md): a management-ready incident record (timeline, evidence, impact, actions, lessons learned).

## How I triage

1. **Scope:** what fired, on which asset or identity, and when?
2. **Enrich:** reputation, asset criticality, user context, prior alerts.
3. **Validate:** can I confirm it with a second data source?
4. **Decide:** false positive, benign true positive, or confirmed. Escalate with evidence attached.
5. **Document:** a record that another analyst or an auditor can follow without asking me.

## About

Syed Fahad Quadri, SOC / Security Analyst, Kansas City, MO.
[Portfolio](https://fahad-quadri.github.io/) · [LinkedIn](https://www.linkedin.com/in/syed-fahad-quadri-8a796a3a8/)
