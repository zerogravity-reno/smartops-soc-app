# Reference: Common Information Model (CIM) Data Models (`cim_data_models`)

The Splunk Common Information Model (CIM) standardizes event field names across diverse vendor log sources (Sysmon, Windows Event Logs, Cisco ASA, Palo Alto Networks, Bind, Suricata, Stream HTTP/DNS, AWS CloudTrail, Zeek).

This reference documents the primary CIM data models used in SmartOps SOC App security telemetry:
1. **Network Resolution (DNS)**
2. **Network Traffic (Flows)**
3. **Endpoint Processes**
4. **Authentication**
5. **Web Traffic**
6. **Malware / Threat Intelligence**
7. **Filesystem Activity**

---

## 1. Network Resolution (DNS) Data Model

The Network Resolution model standardizes DNS requests, responses, reverse lookups, and zone transfers.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `src` / `src_ip` | String (IP) | Client IP address making the DNS query | `"192.168.1.105"`, `"10.0.1.42"` |
| `src_port` | Integer | Client source port | `54210` |
| `dest` / `dest_ip` | String (IP) | DNS server IP address | `"192.168.1.1"`, `"8.8.8.8"` |
| `dest_port` | Integer | DNS server destination port (usually 53) | `53` |
| `query` | String | Domain name queried | `"coinhive.com"`, `"pool.supportxmr.com"` |
| `query_type` | String | DNS record type requested | `"A"`, `"AAAA"`, `"TXT"`, `"MX"`, `"CNAME"` |
| `reply_code` | String | DNS response RCODE | `"NoError"`, `"NXDomain"`, `"ServFail"`, `"Refused"` |
| `answer` / `answers` | String / Array | Resolved IP addresses or aliases returned | `"192.0.2.1"`, `["104.28.14.73", "104.28.15.73"]` |
| `transaction_id` | String / Int | DNS query transaction ID | `0x4a12` |
| `vendor_product` | String | Sensor or log vendor product | `"Splunk Stream DNS"`, `"Suricata"` |

### Mapping Rules for Raw Sources
- **`stream:dns`**: Maps `src_ip` -> `src`, `dest_ip` -> `dest`, `query` -> `query`, `name{}` -> `answers`, `reply_code` -> `reply_code`.
- **`suricata` (dns):** Maps `src_ip` -> `src`, `dest_ip` -> `dest`, `dns.rrname` -> `query`, `dns.rdata` -> `answer`, `dns.rcode` -> `reply_code`.
- **Windows DNS Server (`WinEventLog:DNS-Server-Analytical`):** Maps `ClientIP` -> `src`, `QNAME` -> `query`, `QTYPE` -> `query_type`.

### CIM Query Example
```spl
index=botsv3 (sourcetype=stream:dns OR sourcetype=suricata)
| eval domain=lower(coalesce(query, dns_rrname))
| stats count, values(src_ip) as clients, values(answer) as ips by domain
```

---

## 2. Network Traffic (Flows) Data Model

The Network Traffic model standardizes network layer (IP, TCP, UDP, ICMP) session flows, firewall events, and router flow records.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `src` / `src_ip` | String (IP) | Initiating source IP address | `"10.0.1.42"` |
| `src_port` | Integer | Source port number | `49152` |
| `src_mac` | String | Source MAC address | `"00:11:22:33:44:55"` |
| `dest` / `dest_ip` | String (IP) | Destination IP address | `"198.51.100.22"` |
| `dest_port` | Integer | Destination port number | `443`, `80`, `3389` |
| `dest_mac` | String | Destination MAC address | `"AA:BB:CC:DD:EE:FF"` |
| `transport` / `protocol` | String | L4 Transport protocol | `"tcp"`, `"udp"`, `"icmp"` |
| `action` | String | Firewall or security policy action | `"allowed"`, `"blocked"`, `"dropped"`, `"teardown"` |
| `bytes` / `bytes_out` | Integer | Total bytes transferred in flow | `4096` |
| `bytes_in` | Integer | Inbound bytes received | `16384` |
| `packets` | Integer | Total packet count in flow | `32` |
| `duration` | Float | Session duration in seconds | `14.25` |

### Mapping Rules for Raw Sources
- **`stream:ip` / `stream:tcp` / `stream:udp`**: Maps `src_ip`, `dest_ip`, `src_port`, `dest_port`, `bytes_in`, `bytes_out`.
- **Palo Alto Networks (`pan:traffic`)**: Maps `src`, `dest`, `sport` -> `src_port`, `dport` -> `dest_port`, `action`, `bytes`.
- **Cisco ASA (`cisco:asa`)**: Maps `src_ip`, `dest_ip`, `src_port`, `dest_port`, `action`.

### CIM Query Example
```spl
index=botsv3 (sourcetype=pan:traffic OR sourcetype=stream:ip)
| stats sum(bytes_out) as total_out, sum(bytes_in) as total_in, count by src_ip, dest_ip, dest_port
| eval total_mb = round((total_out + total_in) / 1024 / 1024, 2)
| sort - total_mb
```

---

## 3. Endpoint Processes Data Model

The Endpoint Processes model standardizes process creation, process termination, thread injection, and process lineage telemetry across operating systems (Windows, Linux, macOS).

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `host` / `dest` | String | Computer name where process executed | `"BSTOLL-L"`, `"WORKSTATION-01"` |
| `user` | String | Account executing the process | `"AzureAD\\BudStoll"`, `"SYSTEM"` |
| `process` / `process_name`| String | Executable name | `"chrome.exe"`, `"powershell.exe"` |
| `process_path` | String | Full filesystem path to executable | `"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"` |
| `process_id` / `pid` | String / Int | Process Identifier (PID) | `9752`, `1044` |
| `parent_process_name` | String | Parent process executable name | `"explorer.exe"`, `"services.exe"` |
| `parent_process_path` | String | Full path to parent executable | `"C:\\Windows\\explorer.exe"` |
| `parent_process_id` | String / Int | Parent Process Identifier (PPID) | `1432` |
| `process_current_directory`| String | Working directory at launch | `"C:\\Users\\BudStoll\\Downloads"` |
| `process_integrity_level` | String | Windows Integrity level | `"Medium"`, `"High"`, `"System"` |
| `command_line` / `cmd` | String | Full command-line arguments string | `"powershell.exe -ExecutionPolicy Bypass -File script.ps1"` |
| `hashes` / `md5` / `sha256`| String | Cryptographic hash of executable file | `"SHA256=A1B2C3D4..."` |

### Mapping Rules for Raw Sources
- **Sysmon EventCode 1 (`xmlwineventlog:microsoft-windows-sysmon/operational`)**:
  - `Image` -> `process_path`, `CommandLine` -> `command_line`
  - `ParentImage` -> `parent_process_path`, `ParentCommandLine` -> `parent_command_line`
  - `ProcessId` -> `process_id`, `ParentProcessId` -> `parent_process_id`
  - `Hashes` -> `hashes`, `User` -> `user`
- **Windows Security EventCode 4688 (`WinEventLog:Security`)**:
  - `NewProcessName` -> `process_path`, `CommandLine` -> `command_line`
  - `ParentProcessName` -> `parent_process_path`, `SubjectUserName` -> `user`
  - `NewProcessId` -> `process_id`, `ProcessId` -> `parent_process_id`

### CIM Query Example
```spl
index=botsv3 (sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1) OR (sourcetype=WinEventLog:Security EventCode=4688)
| eval proc_name=coalesce(process_name, Image, NewProcessName)
| eval cmd=coalesce(command_line, CommandLine)
| stats count, values(cmd) as command_lines by ComputerName, User, proc_name
```

---

## 4. Authentication Data Model

The Authentication model standardizes user authentication attempts, logons, logoffs, escalation events, and session lock/unlocks.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `action` | String | Result of authentication attempt | `"success"`, `"failure"`, `"error"` |
| `user` / `src_user` | String | User identity attempting authentication | `"bstoll"`, `"Administrator"` |
| `dest` / `dest_host` | String | Computer or service receiving logon request | `"DC01.corp.contoso.com"` |
| `src` / `src_ip` | String | Source IP or machine originating request | `"10.0.2.15"`, `"WORKSTATION-05"` |
| `logon_type` | Integer / String| Windows Logon Type code | `2` (Interactive), `3` (Network), `10` (RDP) |
| `authentication_method` | String | Protocol or mechanism used | `"Kerberos"`, `"NTLMv2"`, `"Password"`, `"MFA"` |
| `signature_id` / `eventcode`| String / Int | Vendor Event ID code | `4624`, `4625`, `4672`, `4768` |
| `reason` / `sub_status` | String | Failure status or reason code | `"0xc000006a"` (Bad Password) |

### Mapping Rules for Raw Sources
- **`WinEventLog:Security` 4624 (Logon Success)**:
  - `TargetUserName` -> `user`, `WorkstationName` -> `src`, `LogonType` -> `logon_type`
  - `IpAddress` -> `src_ip`, `action="success"`.
- **`WinEventLog:Security` 4625 (Logon Failure)**:
  - `TargetUserName` -> `user`, `WorkstationName` -> `src`, `LogonType` -> `logon_type`
  - `IpAddress` -> `src_ip`, `SubStatus` -> `reason`, `action="failure"`.

### CIM Query Example
```spl
index=botsv3 sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)
| eval action=if(EventCode=4624, "success", "failure")
| stats count by TargetUserName, LogonType, IpAddress, action
```

---

## 5. Web Traffic Data Model

The Web model standardizes HTTP/HTTPS request and response telemetry from web servers, proxies, and application firewalls.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `src` / `src_ip` | String (IP) | Client IP address making HTTP request | `"192.168.1.105"` |
| `dest` / `dest_ip` | String (IP) | Target HTTP server IP address | `"104.28.14.73"` |
| `dest_port` | Integer | Destination HTTP port | `80`, `443`, `8080` |
| `site` / `http_host` | String | HTTP `Host` header value | `"coinhive.com"`, `"api.github.com"` |
| `uri` / `uri_path` | String | Requested URI path and query string | `"/lib/coinhive.min.js?pool=xmr"` |
| `http_method` | String | HTTP request method | `"GET"`, `"POST"`, `"HEAD"`, `"PUT"` |
| `status` / `http_status` | Integer | HTTP response status code | `200`, `302`, `404`, `500` |
| `user_agent` | String | Client HTTP `User-Agent` header | `"Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."` |
| `http_referrer` | String | Client HTTP `Referer` header | `"https://example.com/index.html"` |

---

## 6. Malware & Threat Intelligence Data Model

Standardizes antivirus detection events, intrusion prevention alerts, and threat intelligence matches.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `signature` | String | Threat alert or signature name | `"Win32.Trojan.Coinminer"`, `"ET MALWARE Coinhive"` |
| `category` | String | Malware category | `"Cryptominer"`, `"Ransomware"`, `"Trojan"` |
| `severity` | String | Alert severity level | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `file_name` / `file_path` | String | Malicious file name or path | `"coinhive.js"`, `"C:\\Temp\\miner.exe"` |
| `file_hash` | String | SHA256 / MD5 hash of malicious file | `"d41d8cd98f00b204e9800998ecf8427e"` |
| `src` / `dest` | String | Affected source/destination host or IP | `"10.0.1.42"` |

---

## 7. Filesystem Activity Data Model

Standardizes file creation, modification, deletion, and permission changes across host systems.

### Canonical Schema

| Field Name | Type | Description | Example Values |
|---|---|---|---|
| `file_name` | String | Executable or document file name | `"mimikatz.exe"`, `"payload.ps1"` |
| `file_path` | String | Full directory path to file | `"C:\\Users\\Public\\payload.ps1"` |
| `action` | String | File action | `"created"`, `"modified"`, `"deleted"`, `"renamed"` |
| `user` | String | Account performing file modification | `"AzureAD\\BudStoll"` |
| `process_name` | String | Executable making file change | `"cmd.exe"`, `"powershell.exe"` |

---

## 8. Cross-Vendor Field Normalization Reference Matrix

| Raw Vendor Field | Standardized CIM Field | Target CIM Data Model | Sample Vendor Log Source |
|---|---|---|---|
| `src_ip`, `src`, `ClientIP`, `c_ip`, `IpAddress` | `src_ip` | Universal | Stream, Palo Alto, WinEventLog |
| `dest_ip`, `dest`, `ServerIP`, `s_ip`, `ComputerName` | `dest_ip` | Universal | Stream, Palo Alto, WinEventLog |
| `query`, `dns_rrname`, `QNAME` | `query` | Network Resolution | `stream:dns`, `suricata`, Windows DNS |
| `Image`, `NewProcessName`, `process_name`, `process` | `process_name` | Endpoint Processes | Sysmon 1, WinEventLog 4688 |
| `CommandLine`, `cmd`, `args` | `command_line` | Endpoint Processes | Sysmon 1, WinEventLog 4688 |
| `TargetUserName`, `User`, `SubjectUserName` | `user` | Authentication / Endpoint | WinEventLog 4624, Sysmon 1 |
| `LogonType`, `logon_type` | `logon_type` | Authentication | WinEventLog 4624 / 4625 |
| `site`, `http_host`, `hostname`, `Host` | `site` | Web Traffic | `stream:http`, IIS, NGINX |
| `uri`, `uri_path`, `cs_uri_stem` | `uri` | Web Traffic | `stream:http`, IIS, NGINX |
