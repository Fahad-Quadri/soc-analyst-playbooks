# 03 - IDS/IPS Alert Validation

**Goal:** decide whether a signature hit is a real intrusion, a scan, or noise, using packet-level evidence.
**ATT&CK:** T1046 (Network service discovery), T1071 (Application layer protocol)

## Steps
1. **Read the signature:** what does it claim to detect, and what traffic would truly match it?
2. **Pull the packets** for the flow (pcap or full-session capture) in Wireshark.
3. **Check the basics**
   - Direction: inbound, outbound, or lateral?
   - Handshake completed? A SYN-only hit is a probe, not a session.
   - Did the server **respond**, and with what? A reset or no reply often means it failed.
4. **Inspect the payload:** does it contain the exploit string, or only trigger a loose pattern match?
5. **Correlate**
   - Same source touching many ports or hosts: scanning (compare against an Nmap-style sweep pattern)
   - Same host making periodic, small, regular outbound calls: possible beaconing
   - Matching EDR / endpoint events on the destination?
6. **Classify:** false positive (tune), benign scan (authorized?), failed attempt (block + monitor), or confirmed compromise (escalate).

## Useful Wireshark filters
```
ip.addr == 10.0.0.5 && tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scan sources
tcp.analysis.retransmission                                         # trouble / flooding
dns.qry.name contains "example"                                     # suspicious lookups
http.request.method == "POST"                                       # outbound data pushes
```

## Document
Signature ID, flow tuple, timestamps, what the packets showed, verdict, and any tuning recommendation.

## Worked example (synthetic)
An IDS signature for a web exploit fires on an inbound request. The capture shows a single SYN-ACK exchange, the request, and a server response of 404 with no payload; the host logs show nothing after the request. The source IP has also probed ten other hosts in the last hour. Verdict: failed scanning attempt. The IP is blocked, the signature is kept, and no escalation is needed.
