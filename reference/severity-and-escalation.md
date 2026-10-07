# Severity & Escalation Matrix

A starting point. Replace thresholds and contacts with your organization's own policy.

## Severity levels
| Level | Definition | Examples | Target response |
|-------|------------|----------|-----------------|
| **Critical** | Active compromise with business impact, or regulated data likely exposed | Ransomware encrypting, confirmed data theft, domain admin compromise | Immediate; incident commander engaged |
| **High** | Confirmed malicious activity, contained or limited scope | Confirmed malware on one workstation, successful phishing credential theft | Within 1 hour |
| **Medium** | Suspicious activity needing investigation, no confirmed impact | Unusual login patterns, policy-violating transfers | Same business day |
| **Low** | Likely benign or informational | Blocked scan, single failed-login burst, already-patched vulnerability | Next business day / batch review |

## Severity modifiers
Raise one level when any of these apply:
- The asset is a server, domain controller, or holds regulated or confidential data
- Privileged or service accounts are involved
- More than one host or user is affected
- Evidence of persistence or lateral movement exists
- The activity is ongoing

Lower one level when the activity was fully blocked and no execution or access occurred.

## Escalation matrix
| Condition | Escalate to | Include |
|-----------|-------------|---------|
| Confirmed compromise of any account or host | Incident response lead / SOC manager | Timeline, IOCs, containment taken |
| Evidence of data exposure (health, payment, personal data) | Compliance / privacy owner and legal | Data type, volume, destination, timestamps |
| Ransomware or destructive activity | Incident commander, IT leadership, business owner | Scope, isolation status, backup state |
| Executive or high-value account involved | Security leadership | Account, activity, actions taken |
| Third-party / customer environment affected | Account manager and customer security contact per contract | Impact, remediation, next update time |

## Handoff note (use for every escalation)
```
WHAT:   one-line summary
WHEN:   first seen / last seen (UTC)
WHERE:  hosts, accounts, systems
EVIDENCE: links to logs, alerts, screenshots, hashes
ACTIONS TAKEN: what I already contained or changed
NEEDED FROM YOU: decision or action requested
NEXT UPDATE: time
```

## Communication rules
- State facts and confidence separately ("confirmed" vs "suspected").
- Do not speculate about attribution or intent in tickets.
- Keep an audit trail of every action with a timestamp.
