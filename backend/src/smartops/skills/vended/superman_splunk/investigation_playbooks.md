# Reference: SOC Investigation & Threat Hunting Playbooks (`investigation_playbooks`)

This reference details step-by-step threat hunting playbooks, investigative decision trees, gap analysis strategies, and multi-stage SPL query templates for SOC analysts and SIEM subagents.

---

## Playbook 1: Browser Cryptomining & In-Browser Execution

### Threat Context
Attackers or malicious scripts execute browser-based WebAssembly cryptominers (e.g. Coinhive, CryptoLoot, CoinImp) or standalone mining executables (XMRig). Webminers connect to WebSocket endpoints or mining proxy pools (e.g., `coinhive.com`, `pool.supportxmr.com`, `mine.moneropool.com`).

### Stage 1: Domain & Web Traffic Scoping
Retrieve all DNS queries and HTTP connections referencing known mining domains.

```spl
# DNS Resolution Check
index=botsv3 sourcetype=stream:dns (query="*coinhive*" OR query="*miners*" OR query="*monero*" OR query="*xmr*")
| stats count, values(src_ip) as clients, values(name{}) as resolved_ips, earliest(_time) as first_seen, latest(_time) as last_seen by query

# HTTP / Web Request Check
index=botsv3 sourcetype=stream:http (site="*coinhive*" OR uri="*coinhive*")
| table _time, src_ip, dest_ip, site, uri, user_agent, status
```

### Stage 2: Process Lineage Correlation
Correlate the client IP address (e.g., `10.0.1.42` / `BSTOLL-L`) to the exact process that initiated the web connection during that time window.

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 ComputerName="BSTOLL-L"
| where match(Image, "(?i)(chrome|firefox|iexplore|msedge|powershell|cmd)[.]exe$")
| table _time, ComputerName, User, Image, ProcessId, ParentImage, CommandLine
```

### Stage 3: Network Connection Verification (Sysmon EventCode 3)
Link the process PID directly to the destination IP or domain.

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=3 ComputerName="BSTOLL-L"
| table _time, Image, ProcessId, SourceIp, DestinationIp, DestinationPort, DestinationHostname
```

### Expected Output Summary Checklist
- [x] Identified domain requested (`coinhive.com`).
- [x] Identified client IP (`10.0.1.42`) and host (`BSTOLL-L`).
- [x] Identified user account (`AzureAD\BudStoll`).
- [x] Identified process name (`chrome.exe`), PID (`9752`), and parent (`explorer.exe`).
- [x] Verified whether connections were allowed or blocked.

---

## Playbook 2: Command & Control (C2) Beaconing & Outbound Flows

### Threat Context
Malware implants establish periodic or jittered outbound connections to external Command and Control (C2) servers over HTTP/S, DNS, or raw TCP sockets.

### Stage 1: DNS Frequency & Entropy Analysis
Identify high-frequency or high-entropy subdomain requests (DNS tunneling / beaconing).

```spl
index=botsv3 sourcetype=stream:dns src_ip="10.0.1.42"
| stats count, dc(query) as unique_subdomains, avg(eval(len(query))) as avg_len by src_ip, dest_ip
| where count > 50 OR avg_len > 30
| sort - count
```

### Stage 2: Periodic Flow Timing Analysis
Detect regular connection intervals (low variance in delta time between flows).

```spl
index=botsv3 sourcetype=stream:tcp src_ip="10.0.1.42"
| streamstats window=2 current=f last(_time) as prev_time by dest_ip
| eval delta = _time - prev_time
| stats count, avg(delta) as avg_interval, stdev(delta) as jitter by src_ip, dest_ip, dest_port
| where count > 20 AND jitter < 5
```

---

## Playbook 3: Credential Access & LSASS Dump (Mimikatz)

### Threat Context
Attackers dump LSASS (Local Security Authority Subsystem Service) memory to extract plaintext passwords or NTLM hashes using Mimikatz, `comsvcs.dll`, or Task Manager.

### Stage 1: Sysmon ProcessAccess Audit (EventCode 10)
Detect processes requesting high-privilege access rights (`0x1410`, `0x1010`, `0x1F0FFF`) to `lsass.exe`.

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=10 TargetImage="*lsass.exe"
| where GrantedAccess="0x1410" OR GrantedAccess="0x1010" OR GrantedAccess="0x1F0FFF"
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, CallTrace
```

### Stage 2: Process Creation Audit (EventCode 1 / 4688)
Detect command lines referencing `rundll32.exe` with `comsvcs.dll` or `MiniDump`.

```spl
index=botsv3 (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1) OR (sourcetype=WinEventLog:Security EventCode=4688)
| eval cmd=coalesce(command_line, CommandLine)
| where match(cmd, "(?i)(comsvcs[.]dll.*#24|MiniDump|lsass|procdump)")
| table _time, ComputerName, User, Image, cmd
```

---

## Playbook 4: Encoded PowerShell & Command Line Obfuscation

### Threat Context
Attackers utilize Base64 encoding (`-enc`, `-encodedcommand`), environment variable expansion, or string concatenation to evade static command-line detection rules.

### Stage 1: Detect Base64 Command Line Flags
```spl
index=botsv3 (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1) OR (sourcetype=WinEventLog:Security EventCode=4688)
| eval cmd=coalesce(command_line, CommandLine)
| where match(cmd, "(?i)-e(?:nc|ncodedcommand|xp)?\s+[A-Za-z0-9+/=]{20,}")
| table _time, ComputerName, User, Image, ParentImage, cmd
```

### Stage 2: Detect Suspicious Execution Flags
Find executions bypassing execution policy or hiding windows (`-nop`, `-w hidden`, `-noni`).

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-nop|-executionpolicy bypass|-w hidden|-noni)")
| stats count, values(CommandLine) as cmds by ComputerName, User, ParentImage
```

---

## Playbook 5: Lateral Movement & Remote Execution

### Threat Context
Adversaries pivot laterally across host endpoints using PsExec, WMI (`wmic process call create`), WinRM, or Remote Desktop Protocol (RDP).

### Stage 1: Network Authentication & Logon Types (EventCode 4624)
Identify network logons (LogonType 3) or RDP logons (LogonType 10) originating from internal IPs.

```spl
index=botsv3 sourcetype=WinEventLog:Security EventCode=4624 (LogonType=3 OR LogonType=10)
| where TargetUserName!="SYSTEM" AND TargetUserName!="*$"
| stats count, values(WorkstationName) as workstations by IpAddress, TargetUserName, LogonType
```

### Stage 2: PsExec & Service Installation Audit (EventCode 7045 / EventCode 17)
Detect new service installations (e.g. `PSEXESVC`).

```spl
index=botsv3 sourcetype=WinEventLog:System EventCode=7045
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceType, StartType
```

---

## Playbook 6: Persistence via Scheduled Tasks & WMI Event Subscriptions

### Threat Context
Adversaries establish persistence across system reboots by registering scheduled tasks or installing permanent WMI event consumers (`__EventFilter`, `CommandLineEventConsumer`).

### Stage 1: Scheduled Task Creation (EventCode 4698 / Sysmon EventCode 1)
```spl
index=botsv3 (sourcetype=WinEventLog:Security EventCode=4698) OR (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 Image="*schtasks.exe")
| table _time, ComputerName, User, TaskName, Command, TaskContent
```

### Stage 2: WMI Event Consumer Audit (Sysmon EventCodes 19, 20, 21)
```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time, ComputerName, User, EventType, Operation, Name, Query, Destination
```

---

## Playbook 7: Outbound Data Exfiltration over HTTPS / DNS

### Threat Context
Data exfiltration involves staging confidential files into archives (e.g., `.zip`, `.7z`, `.rar`) and transmitting them to external infrastructure via cloud storage APIs or DNS TXT queries.

### Stage 1: High Volume HTTP POST Exfiltration
```spl
index=botsv3 sourcetype=stream:http http_method=POST bytes_out > 1000000
| stats sum(bytes_out) as total_bytes, count by src_ip, dest_ip, site, uri, user_agent
| eval mb = round(total_bytes / 1024 / 1024, 2)
| sort - mb
```

### Stage 2: Archive File Creation & Staging
```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=11
| where match(TargetFilename, "(?i)[.](zip|rar|7z|tar|gz)$")
| table _time, ComputerName, Image, TargetFilename
```

---

## Threat Hunting Decision Matrix

```
Is observable a Domain / URL?
├── YES ──> Run Playbook 1 (DNS & HTTP Scoping) ──> Check Sysmon Event 3
└── NO
    Is observable a Host / User?
    ├── YES ──> Check Authentication (4624/4625) ──> Check Sysmon Event 1 (Process Lineage)
    └── Is observable a Hash / File?
        └── YES ──> Query Reputation (VT) ──> Check FileCreate (Sysmon 11) & DLL Load (Sysmon 7)
```
