# 08 - Cloud Identity Anomaly (AWS / Azure / GCP)

**Trigger:** impossible-travel on a cloud console, new access keys, unusual API calls, privilege changes, disabled logging.
**ATT&CK:** T1078.004 (Cloud accounts), T1098 (Account manipulation), T1562.008 (Disable cloud logs), T1530 (Data from cloud storage), T1496 (Resource hijacking)

## Log sources
| Cloud | Identity / control plane | Data plane |
|-------|--------------------------|------------|
| AWS | CloudTrail, IAM Access Analyzer, GuardDuty | S3 access logs, VPC Flow Logs |
| Azure / Entra | Entra sign-in and audit logs, Activity Log, Defender for Cloud | Storage and NSG flow logs |
| GCP | Cloud Audit Logs (Admin Activity, Data Access), Security Command Center | VPC Flow Logs |

## High-signal events
- **Console login** without MFA, or from a new country / ASN
- **New credentials:** access key created, service principal secret added, OAuth consent granted
- **Privilege change:** policy attached, role assignment, owner added
- **Defense evasion:** CloudTrail stopped or deleted, diagnostic settings removed, alerting rules disabled
- **Resource abuse:** many large instances launched in unused regions (cryptomining)
- **Data access:** bulk listing / download from storage buckets, snapshots shared externally

## Triage steps
1. Identify the **principal** (user, role, service principal, access key ID) and the **source** (IP, ASN, user agent, SDK or console).
2. Pull **24 hours before and after** for that principal.
3. Separate **read-only recon** (`List*`, `Describe*`, `Get*`) from **changes** (`Create*`, `Put*`, `Attach*`, `Delete*`).
4. Check for **persistence**: new users, keys, roles, federation, backdoor policies, scheduled functions.
5. Check **blast radius**: which accounts / subscriptions / projects, which regions, which data stores.
6. Check for **logging tampering** first. If logging was disabled, assume other gaps.

## Containment
- Deactivate the access key or disable the principal; revoke active sessions and tokens.
- Remove attacker-created identities and policies after exporting them as evidence.
- Rotate secrets the principal could read (keys in parameter stores, vaults, environment variables).
- Re-enable and verify logging, then review the gap.

## Common false positives
- CI/CD and automation roles making bursts of API calls
- Infrastructure-as-code runs (Terraform / CloudFormation) creating many resources
- Security tooling and scanners listing resources broadly
- Users on VPN or travelling

## Hardening follow-ups
Require MFA for console users, prefer short-lived role credentials over long-lived keys, apply least privilege, and alert on logging changes.

## Document
Principal, source, timeline of API calls grouped by recon / change / data access, resources created or modified, and secrets rotated.

## Worked example (synthetic)
A long-lived access key belonging to a developer shows `ListBuckets` and `GetObject` calls from a hosting-provider IP in a region the team never uses, then `CreateAccessKey` for a second user. The first key is deactivated, the new key is removed after capture, the bucket access is reviewed for exposure, and credentials stored in that account's parameter store are rotated.
