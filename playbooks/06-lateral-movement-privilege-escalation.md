# 06 - Lateral Movement & Privilege Escalation

**Trigger:** admin logons from unusual hosts, new service installs, privileged group changes, credential-dumping detections.
**ATT&CK:** T1021 (Remote services), T1550 (Use alternate authentication material), T1003 (OS credential dumping), T1068 (Exploitation for privilege escalation), T1136 (Create account)

## Windows events to know
| Event ID | Meaning | Why it matters |
|----------|---------|----------------|
| 4624 | Successful logon | Logon type 3 (network) and 10 (RDP) from unexpected sources |
| 4625 | Failed logon | Bursts followed by 4624 from the same source |
| 4648 | Logon with explicit credentials | Common during lateral movement |
| 4672 | Special privileges assigned | Who just got admin-equivalent rights |
| 4688 | Process creation (with command line enabled) | Tooling and one-liners |
| 4697 / 7045 | Service installed | PsExec-style remote execution |
| 4720 / 4728 / 4732 | Account created / added to privileged group | Persistence and escalation |
| 4769 | Kerberos service ticket request | Kerberoasting shows as many tickets with RC4 encryption |
| 1102 | Audit log cleared | Defense evasion |

## Triage steps
1. **Anchor on the account and the first host.** Where did this account normally log on in the last 30 days?
2. **Map the hops:** build a source -> destination list with timestamps from 4624 / 4648 and network flows.
3. **Check the method:**
   - Network logon type 3 + service creation: remote execution
   - RDP (type 10) from a workstation to a server it never touched: suspicious
   - Pass-the-hash / ticket indicators: NTLM logons with no matching interactive logon, unusual Kerberos ticket lifetimes
4. **Check for credential access:** access to `lsass.exe`, `ntds.dit` copies, `reg save` of SAM / SYSTEM hives, tools like Mimikatz-style behaviours reported by EDR.
5. **Check for escalation:** new members in Domain Admins / local Administrators, new accounts, new scheduled tasks or services running as SYSTEM.
6. **Scope:** list every host and account in the chain. Treat each as compromised until cleared.

## Common false positives
- Admin and patching tools (software deployment, vulnerability scanners) logging on broadly
- Helpdesk or jump-server access patterns
- Service accounts with scheduled jobs on many servers

Confirm with the system owner and change calendar before dismissing.

## Containment
- Disable or reset the compromised accounts; revoke active sessions and Kerberos tickets where possible.
- Isolate the pivot hosts via EDR.
- Remove unauthorized group members and accounts; document before deleting.
- If domain-level credentials may be exposed, escalate for a domain-wide credential reset review.

## Document
Hop-by-hop timeline, accounts and hosts involved, tooling observed, persistence found, and the point at which privilege increased.

## Worked example (synthetic)
A workstation account logs on over the network (type 3) to three file servers within four minutes, and event 7045 shows a new service on each. None of these servers were previously accessed from that workstation. EDR on the first server shows a process reading `lsass.exe`. The accounts and hosts are isolated, the services are removed after evidence capture, and the case is escalated as credential theft with lateral movement.
