# 01 - Phishing & BEC Triage

**Trigger:** user report, email-gateway alert, or SIEM detection of a suspicious message or inbox rule.
**ATT&CK:** T1566 (Phishing), T1534 (Internal spearphishing), T1114.003 (Email forwarding rule)

## 1. Preserve evidence first
- Get the original message as `.eml`/`.msg` with full headers. Do not rely on a forwarded copy.
- Record: reporter, time received, recipients, subject, attachment hashes (SHA-256), URLs.
- Handle mail content on a need-to-know basis. Mailboxes may contain sensitive or regulated data (e.g. HIPAA), so collect only what the investigation needs.

## 2. Analyze the message
| Check | What to look for |
|-------|------------------|
| `From` vs `Return-Path` vs `Reply-To` | Mismatch, lookalike domain, free-mail reply address |
| `Received` chain | Unexpected origin, hops that do not match the claimed sender |
| SPF / DKIM / DMARC results | `fail` / `softfail` / `none` on a sender claiming to be internal or a known brand |
| URLs | Defang, then check reputation and redirects; look for display-text vs href mismatch |
| Attachments | Hash lookup, macro-enabled Office files, archive-in-archive, HTML attachments |
| Language | Urgency, payment or gift-card requests, "change of bank details" |

## 3. Scope the blast radius
- Search the mail platform for the same sender, subject, URL, and attachment hash across all mailboxes.
- Who **clicked** or **opened**? Check proxy / DNS / EDR logs for the URL or domain.
- Did anyone submit credentials? If yes, treat the account as compromised (see playbook 02).

## 4. BEC-specific checks
- New **inbox rules** (forward, delete, move-to-RSS/Archive) created recently.
- New **OAuth app consents** or mailbox delegates.
- Sign-ins from new geographies or ASNs shortly before the rule appeared.
- Out-of-band payment or bank-detail change requests tied to the thread.

## 5. Decide
| Outcome | Action |
|---------|--------|
| Benign / marketing | Close with note; tune the rule if it fired wrongly |
| Malicious, no interaction | Purge from mailboxes, block sender / domain / URL, add IOCs |
| Interaction (click / open) | Isolate endpoint if payload suspected, reset credentials, review sessions |
| Confirmed compromise or BEC | **Escalate to incident response**, preserve logs, notify per policy |

## 6. Document
Use the [incident report template](../templates/incident-report.md). Always include the original headers, IOC list, affected users, and exact containment steps with timestamps.
