# Reference: BOTSv3 Dataset Architecture & Sourcetypes (`botsv3_sourcetypes`)

The **Boss of the SOC v3 (BOTSv3)** dataset captures realistic multi-domain enterprise telemetry across Windows endpoints, Linux servers, network sensors, AWS cloud logs, and web security controls during a simulated cyber attack scenario (August 2018).

All BOTSv3 telemetry resides within `index=botsv3`.

---

## 1. BOTSv3 Index & Sourcetype Summary Table

| Sourcetype Category | Sourcetype Identifier | Sensor / Description | Primary Key Fields |
|---|---|---|---|
| **Network Streams** | `stream:dns` | Full-packet DNS queries and answers | `src_ip`, `dest_ip`, `query`, `name{}`, `reply_code` |
| **Network Streams** | `stream:http` | Full HTTP request/response metadata | `src_ip`, `dest_ip`, `site`, `uri`, `user_agent`, `status` |
| **Network Streams** | `stream:dhcp` | DHCP lease allocations | `src_mac`, `lease_ip`, `host` |
| **Network Streams** | `stream:ip` / `stream:tcp` | Packet flow headers & bytes | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `bytes` |
| **Endpoint Telemetry** | `xmlwineventlog:microsoft-windows-sysmon/operational` | Microsoft Sysmon Event Logs | `EventCode`, `Image`, `CommandLine`, `Hashes`, `User` |
| **Endpoint Telemetry** | `WinEventLog:Security` | Windows Security Audit Log | `EventCode`, `TargetUserName`, `WorkstationName`, `NewProcessName` |
| **Endpoint Telemetry** | `WinEventLog:System` | Windows System Log (Services, Drivers) | `EventCode`, `Provider_Name`, `Message` |
| **Endpoint Telemetry** | `WinEventLog:Application` | Windows Application Event Log | `EventCode`, `Source`, `Message` |
| **Perimeter / Firewall** | `pan:traffic` | Palo Alto Networks Firewall Traffic Logs | `src`, `dest`, `sport`, `dport`, `action`, `bytes` |
| **Perimeter / Firewall** | `pan:threat` | Palo Alto Networks Threat Inspection | `src`, `dest`, `threat_name`, `severity` |
| **NIDS / Malware** | `suricata` | Suricata Intrusion Detection System | `src_ip`, `dest_ip`, `alert.signature`, `alert.category` |
| **Cloud Telemetry** | `aws:cloudtrail` | AWS CloudTrail API Audit Logs | `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress` |
| **Cloud Security** | `aws:cloudwatch:guardduty` | AWS GuardDuty Threat Findings | `type`, `severity`, `service.action.actionType` |
| **Linux Host Logs** | `linux_secure` / `syslog` | Authentication & System logs | `process`, `user`, `src_ip`, `message` |

---

## 2. Microsoft Sysmon Event Codes (`xmlwineventlog:.../operational`)

Sysmon provides granular system activity instrumentation on Windows hosts in BOTSv3 (e.g., host `BSTOLL-L`, `WORKSTATION-01`).

### Comprehensive Sysmon Event ID Reference Table

| Event ID | Event Name | High-Value Fields | SOC Threat Hunting Utility |
|---|---|---|---|
| **1** | Process Creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `CurrentDirectory` | Detect malicious process execution, cryptominers, encoded PowerShell, CLI abuse. |
| **2** | Process Change File Creation Time | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` | Detect file timestomping. |
| **3** | Network Connection | `Image`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname` | Correlate executable file to outbound C2 connection or mining pool traffic. |
| **4** | Sysmon Service State Changed | `State`, `Version` | Detect Sysmon tampering or service shutdown. |
| **5** | Process Terminated | `Image`, `ProcessId` | Track process lifespan and abrupt terminations. |
| **6** | Driver Loaded | `ImageLoaded`, `Hashes`, `Signed`, `Signature` | Detect rootkit loading or vulnerable driver exploitation (BYOVD). |
| **7** | Image Loaded (DLL Load) | `Image`, `ImageLoaded`, `Hashes`, `Signed`, `SignatureStatus` | Detect DLL side-loading, unbacked DLL execution, reflective loading. |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `NewThreadId`, `StartAddress` | Detect process injection (e.g. Mimikatz injecting into LSASS). |
| **9** | RawAccessRead | `Image`, `Device` | Detect raw disk reading bypassing API hooks. |
| **10** | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` | Detect LSASS memory dumping or unauthorized process handles. |
| **11** | FileCreate | `Image`, `TargetFilename`, `CreationUtcTime` | Track dropped payloads, webshells, or payload extraction. |
| **12** | Registry Event (Object Create/Delete) | `EventType`, `TargetObject`, `Image` | Track registry persistence key creation. |
| **13** | Registry Event (Value Set) | `EventType`, `TargetObject`, `Details`, `Image` | Track Run keys, RunOnce, Services, or Winlogon modifications. |
| **14** | Registry Event (Key/Value Rename) | `EventType`, `TargetObject`, `NewName`, `Image` | Track registry obfuscation. |
| **15** | FileCreateStreamHash | `TargetFilename`, `CreationUtcTime`, `Hash` | Detect Alternate Data Streams (ADS) and browser zone identifier files. |
| **17** / **18** | Pipe Created / Connected | `PipeName`, `Image` | Detect Named Pipe creation (e.g. PsExec, Cobalt Strike SMB beacons). |
| **19** / **20** / **21**| WMI Event Monitor | `Operation`, `User`, `Name`, `Query` | Detect WMI persistence subscriptions (`__EventFilter`, `__EventConsumer`). |
| **22** | DNS Query | `QueryName`, `QueryStatus`, `QueryResults`, `Image` | Directly link originating executable (`chrome.exe`) to DNS request (`coinhive.com`). |
| **23** | FileDelete (File Delete Archived) | `Image`, `TargetFilename`, `Hashes`, `IsExecutable` | Track self-deleting malware payloads or wiper activity. |
| **24** | ClipboardChange | `Image`, `Hashes`, `ClientInfo` | Monitor sensitive data copied to system clipboard. |
| **25** | ProcessTampering | `Image`, `Type` | Detect process hollowing or process herpaderping. |
| **26** | FileDeleteDetected | `Image`, `TargetFilename` | Log file deletions logged by kernel mini-filter driver. |

### Recommended Sysmon Queries for BOTSv3
```spl
# Find PowerShell processes executing encoded commands
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
| table _time, ComputerName, User, CommandLine, ParentImage

# Correlate process name to outbound IP connection
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=3
| stats count, values(DestinationHostname) as dest_hosts by Image, DestinationIp, DestinationPort

# Detect process access to LSASS memory
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=10 TargetImage="*lsass.exe"
| table _time, ComputerName, SourceImage, GrantedAccess, CallTrace
```

---

## 3. Windows Security Event Log (`WinEventLog:Security`)

Windows Security event log records authentication, account management, authorization, and process creation.

### Detailed Security Event Codes Table

| Event Code | Description | Key Fields | Focus |
|---|---|---|---|
| **4624** | Successful Logon | `TargetUserName`, `TargetDomainName`, `LogonType`, `WorkstationName`, `IpAddress` | Identify user logon events and session types (LogonType 2=Interactive, 3=Network, 10=RDP). |
| **4625** | Failed Logon | `TargetUserName`, `TargetDomainName`, `SubStatus`, `WorkstationName`, `IpAddress` | Brute force or password spraying detection (`SubStatus 0xc000006a` = bad password). |
| **4634** / **4647** | Logoff Event | `TargetUserName`, `TargetDomainName`, `LogonType` | Session duration tracking. |
| **4648** | Logon using explicit credentials | `SubjectUserName`, `TargetUserName`, `TargetServerName` | Detect `runas` command usage or privilege escalation. |
| **4672** | Special Privileges Assigned | `SubjectUserName`, `PrivilegeList` | Administrative logon indicator (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`). |
| **4688** | Process Creation | `NewProcessName`, `CommandLine`, `ParentProcessName`, `SubjectUserName` | Legacy Windows process creation audit log. |
| **4698** / **4702** | Scheduled Task Created/Modified | `TaskName`, `TaskContent`, `SubjectUserName` | Scheduled task persistence mechanisms. |
| **4720** | User Account Created | `TargetUserName`, `SubjectUserName` | Rogue account creation. |
| **4728** / **4732** | Member Added to Group | `TargetUserName`, `GroupName`, `SubjectUserName` | Escalation into Domain Admins or Local Administrators. |
| **4768** / **4769** | Kerberos TGT / TGS Request | `TargetUserName`, `ServiceName`, `TicketOptions`, `TicketEncryptionType` | Kerberoasting detection (`TicketEncryptionType=0x23` rc4-hmac). |
| **4776** | NTLM Authentication | `TargetUserName`, `Workstation`, `Status` | NTLM credential validation. |
| **5140** / **5145** | Network Share Object Access | `ShareName`, `RelativeTargetName`, `AccessMask` | Network share traversal and admin share access (`C$`, `ADMIN$`). |

---

## 4. Network Stream Sourcetypes (`stream:dns`, `stream:http`, `stream:dhcp`)

Splunk Stream provides deep packet inspection metadata without requiring PCAP storage.

### `stream:dns` Specifics
- **Primary Search Fields:** `query`, `query_type`, `src_ip`, `dest_ip`, `name{}`, `reply_code`, `transaction_id`.
- **Common Query Filter:**
  ```spl
  index=botsv3 sourcetype=stream:dns query="*coinhive.com*"
  | stats count by src_ip, query, reply_code
  ```

### `stream:http` Specifics
- **Primary Search Fields:** `site`, `uri`, `http_method`, `user_agent`, `status`, `src_ip`, `dest_ip`, `cookie`, `http_content_type`.
- **Common HTTP Query Filter:**
  ```spl
  index=botsv3 sourcetype=stream:http site="*coinhive.com*" OR uri="*coinhive*"
  | table _time, src_ip, dest_ip, site, uri, user_agent, status
  ```

### `stream:dhcp` Specifics
- **Primary Search Fields:** `src_mac`, `lease_ip`, `hostname`, `dhcp_message_type`.
- Use to map MAC addresses to historical DHCP IP assignments during the BOTSv3 timeframe.

---

## 5. AWS CloudTrail & GuardDuty (`aws:cloudtrail`, `aws:cloudwatch:guardduty`)

### AWS CloudTrail
- **Fields:** `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress`, `requestParameters`.
- Detect IAM user creation, policy modification, S3 bucket enumeration, or EC2 instance launching.

### AWS GuardDuty
- **Fields:** `type`, `severity`, `title`, `service.action.actionType`.
- Detect AWS threat findings such as `Recon:IAMUser/NetworkPermissions`, `UnauthorizedAccess:EC2/TorIPCaller`, or `CryptoCurrency:EC2/BitcoinTool.B!DNS`.

---

## 6. Perimeter & NIDS (`pan:traffic`, `pan:threat`, `suricata`)

### `pan:traffic` & `pan:threat`
- **Fields:** `src`, `dest`, `sport`, `dport`, `app`, `action`, `threat_name`, `bytes`.
- Use to check if perimeter firewall allowed or dropped outbound connections from host `BSTOLL-L`.

### `suricata`
- **Fields:** `event_type`, `src_ip`, `dest_ip`, `alert.signature`, `alert.category`, `alert.severity`.
- Use to retrieve IDS signature alerts generated during the attack scenario.

---

## 7. Linux System Telemetry (`linux_secure`, `syslog`)

- **Fields:** `process`, `pid`, `user`, `src_ip`, `message`, `status`.
- Used to trace SSH logons (`Accepted password for...`, `Failed password for...`), `sudo` command executions, and daemon system messages on Linux endpoints.

---

## 8. BOTSv3 Host & Identity Reference Map

| Entity Name | Entity Type | Role / Context in BOTSv3 |
|---|---|---|
| `BSTOLL-L` | Host | Bud Stoll's workstation (primary target machine). |
| `AzureAD\BudStoll` / `bstoll` | User | Target user account associated with workstation `BSTOLL-L`. |
| `coinhive.com` | Domain | Cryptomining domain queried during the incident. |
| `10.0.1.42` | IP Address | Internal IP address assigned to `BSTOLL-L`. |
| `10.0.1.1` | IP Address | Primary Domain Controller / DNS Server. |
| `10.0.1.254` | IP Address | Internal Default Gateway / Palo Alto Firewall interface. |
| `10.0.2.109` | IP Address | Secondary Linux server host in BOTSv3 environment. |
