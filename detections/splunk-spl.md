# Splunk SPL Detections

Placeholders: replace `index`, `sourcetype`, and field names with your data model (CIM-style names are used where possible). Tune thresholds to your baseline before alerting on them.

## 1. Failed-login burst followed by success (T1110, T1078)
```spl
index=auth sourcetype=auth_logs (action=failure OR action=success)
| bin _time span=15m
| stats count(eval(action="failure")) AS failures
        count(eval(action="success")) AS successes
        dc(user) AS users
        BY _time src
| where failures >= 10 AND successes >= 1
| sort - failures
```
**Why:** a spray or brute force that eventually works is the highest-value auth signal.
**False positives:** shared NAT / VPN egress, service accounts with stale passwords.

## 2. Password spraying: one source, many accounts (T1110.003)
```spl
index=auth sourcetype=auth_logs action=failure
| bin _time span=30m
| stats dc(user) AS distinct_users count AS attempts BY _time src
| where distinct_users >= 8 AND attempts <= distinct_users * 3
```
**Why:** spraying uses few attempts per account across many accounts, so per-account lockouts never fire.

## 3. Impossible travel (T1078)
```spl
index=auth sourcetype=auth_logs action=success
| iplocation src
| sort 0 user _time
| streamstats current=f last(lat) AS prev_lat last(lon) AS prev_lon last(_time) AS prev_time BY user
| eval hours=(_time - prev_time)/3600
| eval km=6371*acos(sin(lat*pi()/180)*sin(prev_lat*pi()/180)
        + cos(lat*pi()/180)*cos(prev_lat*pi()/180)*cos((lon-prev_lon)*pi()/180))
| eval speed_kmh=if(hours>0, km/hours, null())
| where km > 500 AND speed_kmh > 900
```
**False positives:** VPN / proxy egress, mobile carriers, cloud-provider IP geolocation errors. Exclude known egress ranges.

## 4. New inbox forwarding or delete rule (T1114.003, BEC)
```spl
index=o365 sourcetype=o365:management:activity
  (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="Set-Mailbox")
| eval params=mvjoin('Parameters{}.Value', " | ")
| where match(params, "(?i)ForwardTo|ForwardAsAttachmentTo|RedirectTo|DeleteMessage|ForwardingSmtpAddress")
| table _time UserId Operation ClientIP params
```
**Why:** attackers hide replies and exfiltrate mail through rules right after account takeover.
**Next step:** pivot on `UserId` into playbook 02 (sign-ins in the prior 24 h).

## 5. Rare process launched from a user-writable path (T1204, T1059)
```spl
index=endpoint sourcetype=process_creation
  (Image="*\\AppData\\*" OR Image="*\\Temp\\*" OR Image="*\\Downloads\\*")
| stats count dc(host) AS hosts values(ParentImage) AS parents BY Image
| where hosts <= 2
| sort count
```
**Why:** malware often runs from writable paths; legitimate software is usually installed widely.
**False positives:** portable admin tools, developer builds, auto-updaters.

## 6. Possible DNS tunneling / DGA: long, high-entropy queries (T1071.004)
```spl
index=dns sourcetype=dns_logs
| eval qlen=len(query), labels=mvcount(split(query,"."))
| where qlen > 60 OR labels > 6
| stats count dc(query) AS unique_queries BY src
| where unique_queries > 100
| sort - unique_queries
```
**False positives:** CDNs, security products, some SaaS clients. Baseline first.

## Triage after any alert
1. Enrich: user, asset criticality, reputation of the external IP / domain.
2. Confirm with a second data source (endpoint, proxy, email).
3. Decide: false positive (tune), benign true positive, or confirmed (escalate with evidence).
