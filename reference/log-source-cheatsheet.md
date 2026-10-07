# Log Source Cheat Sheet

Which log answers which question. Use it to pick a second data source quickly.

| Question | Primary source | Backup source |
|----------|----------------|---------------|
| Who logged on, from where? | Windows Security (4624 / 4625), IdP / SSO logs | VPN, proxy auth, cloud sign-in logs |
| What process ran, with what arguments? | EDR process telemetry, Sysmon (Event 1), Windows 4688 | Shell history, PowerShell script-block logs (4104) |
| What did it connect to? | EDR network events, Sysmon (Event 3), firewall logs | NetFlow, DNS logs, proxy logs |
| Which domain was looked up? | DNS server / resolver logs, Sysmon (Event 22) | Proxy, EDR |
| What file was created or changed? | EDR file telemetry, Sysmon (Events 11, 23) | File-server audit logs, DLP |
| Was a service or task installed? | Windows 7045 / 4697 / 4698 | EDR persistence detections, autoruns |
| Was an account or group changed? | Windows 4720 / 4728 / 4732 | Directory audit logs, IdP audit logs |
| Was the log cleared or stopped? | Windows 1102 / 104, cloud audit-config events | SIEM ingestion gaps, heartbeat alerts |
| Did an email reach a user? | Mail gateway, message trace | Mailbox audit, EDR browser telemetry |
| Did a user click? | Proxy / DNS / URL-rewrite logs | EDR browser or network events |
| What did a web request do? | Web server access and error logs, WAF | Application and database logs |
| Cloud API activity? | CloudTrail / Entra audit / GCP Audit Logs | VPC / NSG flow logs |

## Time and correlation tips
- Normalize to **UTC** before comparing sources.
- Allow for clock skew (a few seconds to minutes between sources).
- Correlate on stable keys: user, host name **and** IP (DHCP changes), process GUID, session ID.
- Check **ingestion gaps**. Missing logs can look like quiet activity.

## Detection gaps to check on any case
- Command-line logging on process creation enabled?
- PowerShell script-block logging enabled?
- DNS and proxy logs retained long enough for the lookback window?
- Cloud audit logs enabled in **all** regions and accounts?
