# Incident Report: Suspicious Encoded PowerShell via WinRM

## 1. Executive Summary

A suspicious remote PowerShell execution activity was investigated in a controlled cybersecurity lab environment.

The activity originated from a Kali Linux system (`192.168.56.102`) and accessed a Windows endpoint (`192.168.56.101`) through Windows Remote Management (WinRM) over TCP port `5985`.

During the remote session, `wsmprovhost.exe` spawned `powershell.exe`, which executed Base64-encoded commands using the `-enc` parameter.

The encoded commands were decoded and identified as:

* `whoami`
* `hostname`
* `ipconfig`

These commands indicate basic user, host, and network reconnaissance.

Splunk was used to correlate Windows authentication logs, Windows Firewall logs, Sysmon process creation events, and PowerShell Script Block Logging.

**Assessment:** Confirmed suspicious activity in the controlled lab environment.

---

## 2. Incident Details

| Field                | Details                                |
| -------------------- | -------------------------------------- |
| Incident Type        | Suspicious Remote PowerShell Execution |
| Severity             | Medium                                 |
| Status               | TP/Confirmed Suspicious Activity       |
| Detection Platform   | Splunk                                 |
| Source System        | Kali Linux                             |
| Source IP            | `192.168.56.102`                       |
| Target System        | Windows VM                             |
| Target IP            | `192.168.56.101`                       |
| Target Hostname      | `DESKTOP-973UF43`                      |
| Account              | `WinHarsh`                             |
| Remote Protocol      | WinRM                                  |
| Destination Port     | TCP/5985                               |
| Parent Process       | `wsmprovhost.exe`                      |
| Child Process        | `powershell.exe`                       |
| Suspicious Parameter | `-enc`                                 |

---

## 3. Lab Environment

The investigation was performed in an isolated home-lab environment.

```text
Kali Linux
192.168.56.102
     |
     | WinRM / TCP 5985
     v
Windows Endpoint
192.168.56.101
     |
     | Logs
     v
Splunk SIEM
```

### Tools and Telemetry

* Kali Linux
* Evil-WinRM
* Windows
* Splunk
* Sysmon
* Windows Security Events
* Windows Firewall Logs
* PowerShell Script Block Logging

---

## 4. Attack Scenario

The simulated attacker used Kali Linux to identify and access the Windows endpoint through WinRM.

The remote session was established using Evil-WinRM.

After establishing the session, PowerShell was used to execute encoded commands.

The observed activity followed this sequence:

```text
Kali Linux
    |
    | WinRM TCP/5985
    v
Windows Endpoint
    |
    v
wsmprovhost.exe
    |
    v
powershell.exe -enc
    |
    +-- whoami
    +-- hostname
    +-- ipconfig
```

---

## 5. Detection

The primary detection used Sysmon Process Creation events (`EventCode=1`).

The detection identified PowerShell when:

* `powershell.exe` was executed
* `wsmprovhost.exe` was the parent process
* `-enc` or `EncodedCommand` appeared in the command line

### Detection Query

```spl
index=sysmon EventCode=1
Image="*powershell.exe*"
ParentImage="*wsmprovhost.exe*"
(CommandLine="*-enc*" OR CommandLine="*EncodedCommand*")
| table _time host User Image CommandLine ParentImage ParentCommandLine
```

### Detection Significance

The individual indicators are not necessarily malicious by themselves.

However, the combination of:

```text
Remote WinRM session
        +
wsmprovhost.exe
        +
powershell.exe
        +
Encoded PowerShell
        +
Reconnaissance
```

makes the activity suspicious and warrants investigation.

---

## 6. Investigation

### 6.1 Authentication Analysis

Windows Security Event ID `4624` with Logon Type `3` was reviewed to identify the source of the remote authentication.

The investigation identified:

* **Source IP:** `192.168.56.102`
* **Account:** `WinHarsh`
* **Logon Type:** `3`
* **Target Host:** `DESKTOP-973UF43`

This correlated the remote authentication with the simulated attacker system.

---

### 6.2 WinRM Network Analysis

Windows Firewall telemetry was reviewed for connections to WinRM TCP port `5985`.

The observed connection was:

```text
Source IP:        192.168.56.102
Destination IP:   192.168.56.101
Destination Port: 5985
Action:           ALLOW
```

This confirmed network communication between the source and target over the WinRM service.

---

### 6.3 Process Analysis

Sysmon Process Creation telemetry identified the following parent-child relationship:

```text
wsmprovhost.exe
      |
      └── powershell.exe
              |
              └── -enc
```

`wsmprovhost.exe` is associated with Windows Remote Management sessions.

The process relationship therefore provided evidence that PowerShell was executed within the remote WinRM session.

---

### 6.4 PowerShell Analysis

PowerShell Script Block Logging (`EventCode=4104`) was reviewed to obtain additional visibility into the PowerShell activity.

The investigation identified reconnaissance commands associated with the encoded PowerShell execution.

---

## 7. Encoded Command Analysis

Three encoded PowerShell commands were identified.

| Encoded Command            | Decoded Command | Purpose                                |
| -------------------------- | --------------- | -------------------------------------- |
| `dwBoAG8AYQBtAGkA`         | `whoami`        | Identify current user/security context |
| `aABvAHMAdABuAGEAbQBlAA==` | `hostname`      | Identify target hostname               |
| `aQBwAGMAbwBuAGYAaQBnAA==` | `ipconfig`      | Gather network configuration           |

### Interpretation

The commands represent basic reconnaissance activity:

* **User discovery**
* **Host identification**
* **Network configuration discovery**

Base64 encoding alone does not indicate malicious activity. In this case, however, the encoded execution occurred as part of a remote WinRM session and was followed by reconnaissance commands.

---

## 8. Evidence

Supporting evidence is stored in the repository under:

`evidence/`

| Evidence                | File                                  | Purpose                                            |
| ----------------------- | ------------------------------------- | -------------------------------------------------- |
| Attack Simulation       | `01_attack_simulation.png`            | Shows simulated remote WinRM activity from Kali    |
| Encoded PowerShell      | `02_encoded_execution.png` | Shows encoded PowerShell execution                 |
| Splunk Detection        | `03_splunk_detection.png`             | Shows the primary detection result                 |
| Authentication          | `04_authentication_source_ip.png`     | Shows the source IP associated with authentication |
| WinRM Network           | `05_winrm_network_connection.png`     | Shows Dest_ip , network communication to TCP/5985  |
| PowerShell Script Block | `06_powershell_script_block.png`      | Shows PowerShell Script Block telemetry            |

---

## 9. Investigation Timeline

| Time     | Activity                                                |
| -------- | ------------------------------------------------------- |
| 13:13:05 | Remote WinRM authentication observed                    |
| 13:13:10 | Network communication to TCP/5985 observed              |
| 13:15:11 | Encoded PowerShell execution associated with `whoami`   |
| 13:15:43 | Encoded PowerShell execution associated with `hostname` |
| 13:16:08 | Encoded PowerShell execution associated with `ipconfig` |


---

## 10. MITRE ATT&CK Mapping

| Technique                              | ID        | Observed Activity            |
| -------------------------------------- | --------- | ---------------------------- |
| Windows Remote Management              | T1021.006 | Remote access through WinRM  |
| PowerShell                             | T1059.001 | PowerShell command execution |
| System Owner/User Discovery            | T1033     | `whoami`                     |
| System Network Configuration Discovery | T1016     | `ipconfig`                   |

---

## 11. Findings

The investigation established that:

1. Remote access originated from `192.168.56.102`.
2. The Windows endpoint accepted WinRM communication over TCP/5985.
3. A network logon was associated with the remote source IP.
4. `wsmprovhost.exe` spawned `powershell.exe`.
5. PowerShell was executed using the `-enc` parameter.
6. The encoded commands were decoded successfully.
7. The commands performed user, host, and network reconnaissance.
8. Multiple Splunk telemetry sources supported the investigation.

### Final Assessment

**True Positive / Confirmed Suspicious Activity — Controlled Lab Simulation**

The combination of remote WinRM access, encoded PowerShell execution, and reconnaissance behavior represents suspicious activity that should be investigated in a production SOC environment.

No malware execution or persistence was established during this investigation.

---

## 12. Recommended SOC Response

If the same activity were observed in a production environment, the SOC should:

### Triage

* Validate whether the source IP is an authorized administrative system.
* Confirm whether the account legitimately initiated the WinRM session.
* Review surrounding authentication and process events.
* Investigate additional PowerShell activity from the source.
* Search for other systems accessed from the same source IP.

### Containment

If unauthorized activity is confirmed:

* Isolate the affected endpoint according to incident-response procedures.
* Restrict unauthorized WinRM access.
* Investigate the associated account for possible credential compromise.
* Search for additional systems accessed by the same source.

### Detection Improvement

The detection can be strengthened by correlating:

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


## 13. Conclusion

The investigation determined that the Windows endpoint `192.168.56.101` was accessed remotely from `192.168.56.102` using WinRM over TCP/5985.

The remote session resulted in `wsmprovhost.exe` spawning `powershell.exe`, which executed Base64-encoded commands using the `-enc` parameter. The encoded commands were decoded as `whoami`, `hostname`, and `ipconfig`, confirming user, host, and network reconnaissance activity.

Correlation of Windows authentication logs, Firewall telemetry, Sysmon process creation events, and PowerShell Script Block Logging provided sufficient evidence to reconstruct the activity and associate the PowerShell execution with the remote WinRM session.

The activity was assessed as **suspicious remote PowerShell execution with reconnaissance behavior**. In a production environment, the source system, account, and affected endpoint should be validated immediately to determine whether the WinRM access was authorized. If unauthorized, containment and further investigation for credential compromise, lateral movement, persistence, or additional command execution would be warranted.

No evidence of malware execution or persistence was established from the telemetry examined during this investigation.

