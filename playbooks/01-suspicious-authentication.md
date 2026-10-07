# 01 - Suspicious Authentication

**Trigger:** failed-login burst, impossible travel, new-device sign-in, MFA push spam.
**ATT&CK:** T1110 (Brute force), T1078 (Valid accounts), T1621 (MFA request generation)

## Quick classification
| Pattern | Likely | Confirm with |
|---------|--------|--------------|
| Many failures, many usernames, one source | Password spraying | Source reputation; any later success from the same source |
| Many failures, one username | Brute force or user lockout | Helpdesk tickets, service-account misconfig |
| Failures then **success** | Possible compromise | Post-login activity: mailbox rules, new MFA method, data access |
| Two locations faster than travel allows | Impossible travel or VPN/proxy | VPN egress ranges, mobile carrier ASNs, device ID |
| Repeated MFA prompts the user did not start | MFA fatigue | Ask the user directly; check whether any prompt was approved |

## Steps
1. Identify the account, source IP / ASN / geo, user agent, and application.
2. Pull 24 h of activity for the account **before and after** the event.
3. Check whether the source is a known corporate egress, VPN, or travel pattern.
4. If any suspicious success: force sign-out of sessions, reset password, review MFA methods, review mailbox rules and OAuth consents.
5. Check whether the same source touched other accounts.

## Common false positives
- Corporate NAT / VPN egress pooling many users on one IP
- Service accounts with stale credentials in a scheduled job
- Users travelling or on mobile data
- Password-manager or mobile mail-client retry loops

## Escalate when
A successful login follows a failure burst from an unfamiliar source **and** any post-login change occurs (rule, MFA method, forwarding, privilege change).
