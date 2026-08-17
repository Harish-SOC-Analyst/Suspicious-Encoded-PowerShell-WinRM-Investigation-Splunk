# Suspicious Encoded PowerShell WinRM Investigation - Splunk

> A hands-on SOC investigation of suspicious remote PowerShell execution through Windows Remote Management (WinRM), using Splunk to correlate network, authentication, process, and PowerShell telemetry.

---

## Overview

This project demonstrates the investigation of suspicious remote PowerShell execution through Windows Remote Management (WinRM) in a controlled cybersecurity lab environment.

A Kali Linux system was used as the simulated attacker, a Windows endpoint was used as the target, and Splunk was used as the SIEM for investigation and event correlation.

The activity involved:

* Remote WinRM access
* PowerShell execution through `wsmprovhost.exe`
* Base64-encoded PowerShell commands
* User, host, and network reconnaissance
* Windows authentication events
* Windows Firewall network telemetry
* Sysmon Process Creation events
* PowerShell Script Block Logging

The investigation followed the activity from the initial remote connection through PowerShell execution and reconnaissance.

---

## Investigation Scenario

The simulated attacker established a remote WinRM session from Kali Linux to the Windows endpoint.

After the remote session was established, PowerShell was executed using the `-enc` parameter to run Base64-encoded commands.

The decoded commands were:

```text
whoami
hostname
ipconfig
```

These commands were used to perform basic reconnaissance on the target system.

The investigation focused on identifying:

* The source of the remote connection
* The authentication activity
* The WinRM network connection
* The PowerShell parent-child process relationship
* The encoded PowerShell command
* The commands executed after decoding
* The associated reconnaissance activity

---

## Lab Environment

| Component  | Role                          | IP Address       |
| ---------- | ----------------------------- | ---------------- |
| Kali Linux | Simulated Attacker            | `192.168.56.102` |
| Windows VM | Target Endpoint               | `192.168.56.101` |
| Splunk     | SIEM / Investigation Platform | Lab Environment  |

### Technologies Used

* Splunk
* Sysmon
* Windows Event Logs
* Windows Firewall Logs
* PowerShell Script Block Logging
* Windows Remote Management (WinRM)
* Kali Linux
* Evil-WinRM

---

## Attack Flow

```text
┌─────────────────────┐
│     Kali Linux      │
│  192.168.56.102     │
│    Attacker VM      │
└──────────┬──────────┘
           │
           │ WinRM / TCP 5985
           ▼
┌─────────────────────┐
│     Windows VM      │
│  192.168.56.101     │
│   Target Endpoint   │
└──────────┬──────────┘
           │
           │ Remote Session
           ▼
    wsmprovhost.exe
           │
           ▼
     powershell.exe
           │
           │ -enc
           ▼
   Encoded PowerShell
           │
      ┌────┼────┐
      ▼    ▼    ▼
   whoami hostname ipconfig
           │
           ▼
     Splunk Investigation
```

---

## Attack Simulation

The simulated attacker first identified that WinRM was available on the Windows endpoint.

WinRM was accessible through:

```text
TCP/5985
```

A remote WinRM session was then established from Kali Linux.

During the remote session, reconnaissance commands were executed and PowerShell was used with encoded commands.

### Observed Reconnaissance

```text
whoami
hostname
ipconfig
```

The attack simulation evidence is available here:

**[Attack Simulation Evidence](evidence/01_attack_simulation.png)**

---

## Detection

The primary detection was based on Sysmon Process Creation events.

The detection looked for the following combination:

```text
powershell.exe
       +
wsmprovhost.exe
       +
-enc / -EncodedCommand
```

This combination is suspicious because it indicates PowerShell execution within the context of a WinRM remote session using an encoded command.

### Detection Query

**[View Detection SPL](investigation/01%20detection.spl)**

```spl
index=sysmon EventCode=1
Image="*powershell.exe*"
ParentImage="*wsmprovhost.exe*"
(CommandLine="*-enc*" OR CommandLine="*EncodedCommand*")
| table _time host User Image CommandLine ParentImage ParentCommandLine
```

### Detection Result

The detection identified:

| Field          | Observed Value    |
| -------------- | ----------------- |
| Host           | `DESKTOP-973UF43` |
| User           | `WinHarsh`        |
| Process        | `powershell.exe`  |
| Parent Process | `wsmprovhost.exe` |
| Parameter      | `-enc`            |

**[Splunk Detection Evidence](evidence/03_splunk_detection.png)**

---

# Investigation

The investigation correlated multiple telemetry sources to reconstruct the activity.

## 1. Authentication Analysis

Windows Event ID `4624` with Logon Type `3` was used to identify the source of the remote authentication.

**[View Authentication SPL](investigation/02%20authentication.spl)**

The investigation identified:

```text
Source IP:   192.168.56.102
Account:     WinHarsh
Logon Type:  3
Host:        DESKTOP-973UF43
```

**[Authentication Evidence](evidence/04_authentication_source_ip.png)**

---

## 2. WinRM Network Analysis

Windows Firewall telemetry was used to confirm communication with the WinRM service.

**[View WinRM Network SPL](investigation/03%20winrm_network.spl)**

Observed connection:

```text
Source IP:        192.168.56.102
Destination IP:   192.168.56.101
Destination Port: 5985
Action:           ALLOW
```

**[WinRM Network Evidence](evidence/05_winrm_network_connection.png)**

---

## 3. Process Analysis

Sysmon Process Creation telemetry identified the following process relationship:

```text
wsmprovhost.exe
       │
       └── powershell.exe
                │
                └── -enc
```

This established that PowerShell execution occurred in the context of the remote WinRM session.

---

## 4. PowerShell Script Block Analysis

PowerShell Script Block Logging (`EventCode=4104`) was reviewed to obtain additional visibility into the PowerShell activity.

**[View Script Block SPL](investigation/04%20script_block.spl)**

The Script Block telemetry provided additional evidence of the commands executed during the suspicious PowerShell activity.

**[PowerShell Script Block Evidence](evidence/06_powershell_script_block.png)**

---

# Encoded PowerShell Analysis

Three Base64-encoded commands were identified during the investigation.

| Encoded Command            | Decoded Command | Purpose                         |
| -------------------------- | --------------- | ------------------------------- |
| `dwBoAG8AYQBtAGkA`         | `whoami`        | User/security context discovery |
| `aABvAHMAdABuAGEAbQBlAA==` | `hostname`      | Target host identification      |
| `aQBwAGMAbwBuAGYAaQBnAA==` | `ipconfig`      | Network configuration discovery |

Base64 encoding by itself is not malicious. However, in this case the encoded commands were executed through a remote WinRM session and were followed by reconnaissance activity.

**[Encoded PowerShell Evidence](evidence/02_encoded_powershell_execution.png)**

---

# Investigation Timeline

| Time     | Activity                                                |
| -------- | ------------------------------------------------------- |
| 13:13:05 | Remote WinRM authentication observed                    |
| 13:13:10 | Network communication to TCP/5985 observed              |
| 13:15:11 | Encoded PowerShell execution associated with `whoami`   |
| 13:15:43 | Encoded PowerShell execution associated with `hostname` |
| 13:16:08 | Encoded PowerShell execution associated with `ipconfig` |


---

# MITRE ATT&CK Mapping

| Technique                              | ID        | Observed Activity            |
| -------------------------------------- | --------- | ---------------------------- |
| Windows Remote Management              | T1021.006 | Remote access through WinRM  |
| PowerShell                             | T1059.001 | PowerShell command execution |
| System Owner/User Discovery            | T1033     | `whoami`                     |
| System Network Configuration Discovery | T1016     | `ipconfig`                   |

---

# Key Findings

The investigation established that:

1. The remote activity originated from `192.168.56.102`.
2. The target Windows endpoint was `192.168.56.101`.
3. WinRM communication occurred over TCP/5985.
4. A Windows network authentication event was associated with the remote activity.
5. `wsmprovhost.exe` spawned `powershell.exe`.
6. PowerShell was executed using the `-enc` parameter.
7. The encoded commands were successfully identified and decoded.
8. The commands performed user, host, and network reconnaissance.
9. Multiple Splunk telemetry sources supported the investigation.

### Analyst Assessment

**Classification:** Confirmed Suspicious Activity — Controlled Lab Simulation

**Severity:** Medium

The combination of remote WinRM access, encoded PowerShell execution, and reconnaissance behavior represents suspicious activity that should be investigated in a production SOC environment.

No evidence of malware execution or persistence was established from the telemetry examined during this investigation.

---

# Recommended SOC Response

If similar activity were observed in a production environment, the SOC should:

### Triage

* Validate whether the source IP belongs to an authorized administrative system.
* Confirm whether the account legitimately initiated the WinRM session.
* Review surrounding authentication and process events.
* Investigate additional PowerShell activity from the source.
* Search for other systems accessed from the same source IP.

### Containment

If unauthorized activity is confirmed:

* Isolate the affected endpoint according to incident-response procedures.
* Restrict unauthorized WinRM access.
* Investigate the associated account for potential credential compromise.
* Search for additional systems accessed from the same source.

### Detection Improvement

A stronger detection strategy can correlate:

```text
WinRM Network Activity
        +
Windows Authentication
        +
wsmprovhost.exe
        +
Encoded PowerShell
        +
PowerShell Script Block Logging
```

Approved administrative IPs can also be maintained in a lookup to reduce false positives.

---

# Evidence

All investigation screenshots are stored in the [`evidence/`](evidence/) directory.

| Evidence                     | File                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------- |
| Attack Simulation            | [`01_attack_simulation.png`](evidence/01_attack_simulation.png)                       |
| Encoded PowerShell Execution | [`02_encoded_powershell_execution.png`](evidence/02_encoded_powershell_execution.png) |
| Splunk Detection             | [`03_splunk_detection.png`](evidence/03_splunk_detection.png)                         |
| Authentication Source IP     | [`04_authentication_source_ip.png`](evidence/04_authentication_source_ip.png)         |
| WinRM Network Connection     | [`05_winrm_network_connection.png`](evidence/05_winrm_network_connection.png)         |
| PowerShell Script Block      | [`06_powershell_script_block.png`](evidence/06_powershell_script_block.png)           |

---

# Investigation Queries

All SPL queries used during the investigation are available in the [`investigation/`](investigation/) directory.

| Query                                                            | Purpose                                          |
| ---------------------------------------------------------------- | ------------------------------------------------ |
| [`01 detection.spl`](investigation/01%20detection.spl)           | Detect encoded PowerShell executed through WinRM |
| [`02 authentication.spl`](investigation/02%20authentication.spl) | Identify remote authentication and source IP     |
| [`03 winrm_network.spl`](investigation/03%20winrm_network.spl)   | Investigate WinRM network activity               |
| [`04 script_block.spl`](investigation/04%20script_block.spl)     | Review PowerShell Script Block Logging           |

---

# Incident Report

The complete investigation report contains the detailed incident analysis, evidence interpretation, timeline, findings, and recommended response.

**[📄 View Full Incident Report](incident-report/incident-report.md)**

---

# Repository Structure

```text
Suspicious-Encoded-PowerShell-WinRM-Investigation-Splunk/
│
├── README.md
│
├── investigation/
│   ├── 01 detection.spl
│   ├── 02 authentication.spl
│   ├── 03 winrm_network.spl
│   └── 04 script_block.spl
│
├── evidence/
│   ├── 01_attack_simulation.png
│   ├── 02_encoded_powershell_execution.png
│   ├── 03_splunk_detection.png
│   ├── 04_authentication_source_ip.png
│   ├── 05_winrm_network_connection.png
│   └── 06_powershell_script_block.png
│
└── incident-report/
    └── incident-report.md
```

---

## Disclaimer

This investigation was performed in a controlled cybersecurity lab environment for educational and SOC analyst training purposes.

The IP addresses, accounts, commands, and activity described in this repository belong to the isolated lab environment and should not be interpreted as real-world malicious infrastructure.

