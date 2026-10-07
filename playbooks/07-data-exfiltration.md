# 07 - Data Exfiltration

**Trigger:** large outbound transfers, DLP alerts, unusual cloud-storage uploads, archive creation followed by outbound traffic.
**ATT&CK:** T1041 (Exfiltration over C2 channel), T1048 (Exfiltration over alternative protocol), T1567 (Exfiltration to web service), T1560 (Archive collected data)

## What exfiltration usually looks like
1. **Collect:** large reads from a share, database, or mailbox
2. **Stage:** archive creation (`.zip`, `.7z`, `.rar`) in a temp or user directory
3. **Move:** outbound upload to cloud storage, file-sharing sites, personal email, or a raw IP
4. **Cover:** deleted archives, cleared logs

## Triage questions
| Question | Source |
|----------|--------|
| How much data left, and over how long? | Proxy / firewall byte counts, NetFlow |
| Where did it go? | Destination domain / IP reputation, category, registration age |
| Which account and host? | Proxy auth logs, EDR, VPN logs |
| What data was it? | File access logs, DLP match, classification labels |
| Is the transfer normal for this user? | 30-day baseline of outbound volume |
| Was a sanctioned tool used? | Approved cloud-storage and transfer inventory |

## Quick checks
- Compare outbound bytes to the user's own baseline, not the fleet average.
- Look for **uploads to personal cloud accounts** from corporate devices.
- Look for DNS with long encoded subdomains (tunneling), and for HTTPS to rare destinations with steady small posts (beaconing).
- Check for **archive creation** shortly before the transfer.
- Check whether the user recently gave notice or changed roles (route this through HR / management confidentially, and only with authority to do so).

## Decide
| Verdict | Action |
|---------|--------|
| Approved business transfer | Document, ask owner to confirm, close |
| Policy violation, no malicious intent | Notify manager / compliance per policy, retrain, tighten DLP rule |
| Suspected insider or compromised account | Preserve logs, contain account, escalate to incident response and legal |
| Confirmed external theft | Incident response, legal / privacy counsel, regulatory notification assessment |

## Containment
- Block the destination at proxy / firewall after recording it.
- Suspend the account or revoke tokens; isolate the host if compromise is suspected.
- Preserve evidence in its original state; limit access to the case.

## Regulated data
If the data may include health, payment-card, or personal information, notify the compliance / privacy owner early. Breach-notification clocks can start when exposure is reasonably suspected, not only when it is proven.

## Document
Data type and volume, destination, account / host, timeline, evidence preserved, decisions and approvers.

## Worked example (synthetic)
A user's outbound volume jumps from a typical 40 MB per day to 6 GB in one evening, to a consumer file-sharing domain. EDR shows a `.7z` archive created from a shared project folder 20 minutes earlier. The account is signed out, the destination is blocked, and the case is escalated to incident response and compliance because the folder is classified as confidential.
