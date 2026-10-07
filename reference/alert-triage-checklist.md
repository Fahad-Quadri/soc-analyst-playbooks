# Alert Triage Checklist

One page to run on **every** alert, whatever the source.

## 1. Understand the alert
- [ ] What rule fired, and what is it designed to detect?
- [ ] When did it fire, and when did the activity actually occur (UTC)?
- [ ] Which asset, user, and source / destination are involved?
- [ ] Is this the first time, or a repeat? Check the last 30 days.

## 2. Enrich
- [ ] Asset criticality and owner
- [ ] User role, location, recent changes (travel, leave, new hire)
- [ ] IP / domain / hash reputation from more than one source
- [ ] Related alerts on the same host, user, or IOC

## 3. Validate with a second source
Never close or escalate on a single data source.

| Alert source | Cross-check with |
|--------------|------------------|
| SIEM correlation rule | Raw logs, then endpoint or network data |
| EDR detection | Process tree, network connections, file activity |
| IDS / IPS signature | Packet capture, server response, host logs |
| Email gateway | Original message headers, mailbox search, click logs |
| Authentication alert | VPN, proxy, device, and cloud sign-in logs |

## 4. Decide
- [ ] **False positive:** explain why, and suggest a tuning change
- [ ] **Benign true positive:** confirm with the owner and record who approved it
- [ ] **Suspicious / needs more info:** state exactly what is missing and who can provide it
- [ ] **Confirmed malicious:** contain, escalate, and start the incident record

## 5. Close properly
- [ ] Verdict and evidence recorded in the ticket
- [ ] IOCs added to blocklists or watchlists where appropriate
- [ ] Detection tuning or gap noted
- [ ] If escalated, handoff note sent (see [severity and escalation](severity-and-escalation.md))

## Common triage mistakes
- Closing because the alert is "usually noisy"
- Trusting one reputation source
- Ignoring timing: activity at 3 a.m. local time is different from 3 p.m.
- Skipping the lookback: the alert is often the **last** step of an intrusion, not the first
- Not recording why a decision was made, so the next analyst repeats the work
