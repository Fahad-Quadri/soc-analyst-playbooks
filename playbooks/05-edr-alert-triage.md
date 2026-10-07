# 05 - EDR Alert Triage

**Trigger:** CrowdStrike, SentinelOne, Cortex XDR, Defender, or similar endpoint detection.
**ATT&CK:** depends on detection. Map the technique shown in the alert first.

## The five questions
1. **What** executed? (process, command line, hash, signer)
2. **Who** ran it? (user, privilege level, interactive or service)
3. **From where** did it come? (parent process, download source, email, USB)
4. **What did it touch?** (files, registry, network, other processes)
5. **Is it normal here?** (seen on other hosts, part of an approved tool)

## Fast triage table
| Signal | Leans benign | Leans malicious |
|--------|--------------|-----------------|
| Signer | Valid, known vendor | Unsigned, revoked, or mismatched |
| Path | `Program Files`, `System32` | `AppData`, `Temp`, `Downloads`, `ProgramData` |
| Parent | Expected installer or shell | Office, browser, PDF reader, script host |
| Command line | Plain, documented switches | Encoded, obfuscated, `-nop -w hidden`, download cradles |
| Prevalence | Many hosts | One or two hosts |
| Network | Vendor / update domains | New domain, raw IP, rare port |
| Timing | Business hours, change window | Off-hours, right after a user report |

## Enrichment checklist
- Hash reputation (multiple sources) and first-seen date
- Domain / IP reputation and registration age
- Same detection on other hosts in the last 30 days?
- User: role, recent travel, recent helpdesk tickets
- Asset: criticality, data classification, patch level

## Decide
| Verdict | Action |
|---------|--------|
| False positive | Close with reason; request an exclusion only through the change process |
| Benign true positive (pentest, admin tool) | Confirm with the owner in writing, then close |
| Suspicious | Contain the host (EDR isolation), gather timeline, escalate |
| Confirmed malicious | Follow [playbook 04](04-malware-ransomware-triage.md) and the escalation matrix |

## Pitfalls
- **Quarantined does not mean contained.** Check whether the process ran before it was blocked and what it spawned.
- Do not whitelist a hash because it "looks like" a known tool; verify the signer and path.
- A clean detection on one host does not clear the others. Search the fleet for the hash and the behaviour.

## Document
Detection ID, host, user, process tree summary, verdict with evidence, and any tuning request.

## Worked example (synthetic)
EDR alerts on `powershell.exe` with a Base64 command line, parent `excel.exe`, user in Finance, one host only. Decoding the command shows a download cradle to a recently registered domain. The domain is blocked, the host is isolated, and the file the macro dropped is collected for analysis. A fleet search finds no other hosts, so the case is escalated as a confirmed phishing-delivered loader with a single-host scope.
