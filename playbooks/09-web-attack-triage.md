# 09 - Web Attack Triage

**Trigger:** WAF alert, spike of 4xx / 5xx, scanner signatures, suspicious requests in web server logs.
**ATT&CK:** T1190 (Exploit public-facing application), T1595 (Active scanning), T1505.003 (Web shell)

## Classify the traffic
| Pattern in logs | Likely | Notes |
|-----------------|--------|-------|
| Hundreds of 404s across many paths from one IP | Directory / vulnerability scanning | Usually low impact unless something returns 200 |
| `' OR 1=1`, `UNION SELECT`, `sleep(`, encoded quotes in parameters | SQL injection attempts | Check response size and status for success |
| `<script>`, `onerror=`, `javascript:` in parameters | XSS attempts | Check whether input is reflected or stored |
| `../`, `%2e%2e%2f`, `/etc/passwd`, `boot.ini` | Path traversal / LFI | A 200 with matching content is critical |
| Long, repeated POSTs to a login URL | Credential stuffing | See [playbook 01](01-suspicious-authentication.md) |
| Requests with `${jndi:`, `() { :;};` or similar | Known exploit probes | Match to the current advisory list |
| Single request to an unusual `.php` / `.jsp` / `.aspx` that then receives traffic | Possible web shell | Check file creation time and content |

## Did it work? (the key question)
1. **Response codes:** 200 on an attack request is more important than 1,000 blocked 403s.
2. **Response size:** an unusually large response to an injection attempt may mean data was returned.
3. **Timing:** blind SQL injection often shows consistent multi-second delays.
4. **Server-side evidence:** new files in web directories, new processes spawned by the web server user, outbound connections from the web host.
5. **Database logs:** unusual queries or errors from the app account.

## Web shell hunt
- Files in web roots modified after the last deployment
- Web server process spawning `cmd`, `sh`, `powershell`, or `bash`
- Requests to rarely used paths returning small, consistent responses
- Compare web root hashes to a known-good deployment

## Containment
- Block the offending IPs or ASNs at the WAF / firewall (treat as a short-term measure; attackers rotate).
- If exploitation is suspected: isolate the host, preserve disk and memory, and take the application offline if needed.
- Patch or apply a virtual patch (WAF rule) for the targeted vulnerability.
- Rotate application and database credentials the host could access.

## Common false positives
- Authorized vulnerability scans (confirm the scanner IP and window)
- Uptime monitors and SEO crawlers
- Misconfigured clients retrying broken URLs

## Document
Source IPs, targeted URLs and parameters, whether any request succeeded, server-side evidence, containment, and the patch / WAF change made.

## Worked example (synthetic)
A WAF reports 3,000 requests from one IP over ten minutes. Most are 403s, but a handful of requests to a legacy `/search` endpoint return 200 with responses ten times larger than normal and the web server user starts a shell process afterward. This is treated as a suspected successful injection with possible code execution, so the host is isolated and escalated.
