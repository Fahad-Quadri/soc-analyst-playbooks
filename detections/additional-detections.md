# Additional Splunk Detections

Complements [splunk-detection-library](https://github.com/Fahad-Quadri/splunk-detection-library) (brute force, password spraying, encoded PowerShell, Office spawning a shell, privileged group changes, log clearing, DNS tunneling, impossible travel). These two cover gaps it does not.

Example queries. Placeholders: replace `index`, `sourcetype`, and field names with your data model. Tune thresholds to your baseline before alerting.

## 1. New inbox forwarding or delete rule (T1114.003, BEC)
```spl
index=o365 sourcetype=o365:management:activity
  (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="Set-Mailbox")
| eval params=mvjoin('Parameters{}.Name', " | ") . " || " . mvjoin('Parameters{}.Value', " | ")
| where match(params, "(?i)ForwardTo|ForwardAsAttachmentTo|RedirectTo|DeleteMessage|ForwardingSmtpAddress")
| table _time UserId Operation ClientIP params
```
**Why:** attackers hide replies and exfiltrate mail through rules right after account takeover.
**Next step:** pivot on `UserId` into [playbook 01](../playbooks/01-suspicious-authentication.md) (sign-ins in the prior 24 h).
**False positives:** users who legitimately forward to a personal or shared mailbox; confirm with the user.

## 2. Rare process launched from a user-writable path (T1204, T1059)
```spl
index=endpoint sourcetype=process_creation
  (Image="*\\AppData\\*" OR Image="*\\Temp\\*" OR Image="*\\Downloads\\*")
| stats count dc(host) AS hosts values(ParentImage) AS parents BY Image
| where hosts <= 2
| sort count
```
**Why:** malware often runs from writable paths; legitimate software is usually installed widely.
**False positives:** portable admin tools, developer builds, auto-updaters.
