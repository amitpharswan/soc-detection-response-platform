# Stage 5 — Windows PowerShell Encoded Command Execution Detection and Investigation

## 1. Overview

This lab validated detection of Windows PowerShell processes launched with the `-EncodedCommand` or abbreviated `-enc` parameter. The test used a harmless command that printed a marker string. Splunk collected Windows process-creation and PowerShell script-block events, detected the encoded process launch, triggered a scheduled alert, and supported investigation.

| Metadata | Details |
|---|---|
| Scenario | Encoded PowerShell command execution |
| Windows host | `DESKTOP-PPSKJ22` |
| Test account | `window` |
| Splunk index | `main` |
| Security event source | `WinEventLog:Security` |
| PowerShell event source | `WinEventLog:Microsoft-Windows-PowerShell/Operational` |
| Primary event | 4688 — Process Creation |
| Supporting event | 4104 — PowerShell Script Block Logging |
| Outcome | Detection and alert validated during authorized lab testing |

Encoded PowerShell is not inherently malicious. The command, account, host, parent process, and surrounding activity must be reviewed before assigning incident severity.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | Windows 11 Home ARM |
| Hostname | `DESKTOP-PPSKJ22` |
| Account used for test | `window` |
| SIEM | Splunk Enterprise on macOS |
| Forwarder | Splunk Universal Forwarder |
| Index | `main` |
| Security source | `WinEventLog:Security` |
| PowerShell source | `WinEventLog:Microsoft-Windows-PowerShell/Operational` |

## 3. Telemetry Configuration

### 3.1 PowerShell Script Block Logging

Enabled the following policy:

```text
HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Configured value:

```text
EnableScriptBlockLogging = 1
```

This enables PowerShell script-block logging, which records script content in the PowerShell Operational log when applicable.

### 3.2 PowerShell Operational event collection

The following stanza was added to the Windows Universal Forwarder `inputs.conf`:

```ini
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
renderXml = 1
```

The existing Windows Security event collection was retained. The PowerShell Operational source was verified as arriving in Splunk.

### 3.3 Process Creation auditing and command-line logging

Process Creation auditing was verified as enabled.

Command-line inclusion for process creation was enabled at:

```text
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

Configured value:

```text
ProcessCreationIncludeCmdLine_Enabled = 1
```

This setting allows Event 4688 to include command-line information when Windows records it.

## 4. Events Used for Detection and Investigation

| Event ID | Log source | Purpose |
|---|---|---|
| 4688 | Windows Security | Process creation, process path, parent process, account, and command line |
| 4104 | PowerShell Operational | PowerShell script-block content |

Event 4688 is the primary detection source because it records the process launch and command-line parameter. Event 4104 is supporting evidence that can help an analyst inspect the script content.

A close timestamp alone does not prove that two events belong to the same process. Process ID and other available context should be checked before describing events as definitively correlated.

## 5. Controlled Lab Simulation

A harmless PowerShell command was encoded using Base64 and executed:

```powershell
$Command = 'Write-Output "SOC_LAB_ENCODED_TEST_2"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)

powershell.exe -NoProfile -EncodedCommand $EncodedCommand
```

Expected output:

```text
SOC_LAB_ENCODED_TEST_2
```

The command printed a test marker only. It did not modify system configuration.

## 6. Detection Engineering in Splunk

### 6.1 Confirm Event 4688 ingestion

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Security"
earliest=-30m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id="4688"
| table _time host sourcetype _raw
| sort -_time
```

### 6.2 Inspect PowerShell process-creation fields

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Security"
earliest=-30m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name='NewProcessName'>(?<process_name>.*?)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<command_line>.*?)</Data>"
| rex field=_raw "<Data Name='ParentProcessName'>(?<parent_process>.*?)</Data>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<executing_user>.*?)</Data>"
| search event_id="4688"
| where match(process_name,"(?i)(?:^|\\)(?:powershell|pwsh)\.exe$")
| table _time host executing_user process_name command_line parent_process
| sort -_time
```

This search narrows Event 4688 records to `powershell.exe` or `pwsh.exe` and displays the process context.

### 6.3 Operational detection SPL

The following is the improved operational search. It retains the original detection logic and adds an explicit PowerShell process-name filter so that an unrelated process with an encoded-command-like argument is not treated as a PowerShell detection.

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Security"
earliest=-10m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name='NewProcessName'>(?<process_name>.*?)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<command_line>.*?)</Data>"
| rex field=_raw "<Data Name='ParentProcessName'>(?<parent_process>.*?)</Data>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<executing_user>.*?)</Data>"
| search event_id="4688"
| where match(process_name,"(?i)(?:^|\\)(?:powershell|pwsh)\.exe$")
| where match(command_line,"(?i)(?:^|\s)-(?:EncodedCommand|enc)(?:\s|=|$)")
| eval detection_name="PowerShell Encoded Command Execution"
| eval severity="High"
| table _time host executing_user process_name command_line parent_process detection_name severity
| sort -_time
```

The search:

1. Searches Windows Security events from the target host.
2. Extracts the event ID, process path, command line, parent process, and account.
3. Filters for Event 4688.
4. Restricts the process to Windows PowerShell (`powershell.exe`) or PowerShell 7+ (`pwsh.exe`).
5. Detects the `-EncodedCommand` or `-enc` command-line parameter.
6. Returns the process context for analyst review.

**Validation note:** Test the process-name regular expression against the raw Event 4688 records in your Splunk environment. The process path is expected to end in `powershell.exe` or `pwsh.exe`. If your XML field extraction or quoting differs, adjust the `rex` extraction to match the raw event.

### 6.4 Supporting Event 4104 search

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
earliest=-30m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id="4104"
| table _time host sourcetype _raw
| sort -_time
```

Use the raw event to inspect the script-block content and any available process metadata. Do not assume that every 4104 event is malicious or that every 4104 event can be paired with a 4688 event using timestamp alone.

### 6.5 Scheduled alert configuration

| Setting | Recorded value |
|---|---|
| Alert name | `Windows - PowerShell Encoded Command Execution` |
| Type | Scheduled |
| Schedule | Every 5 minutes |
| Search time range | Last 10 minutes |
| Trigger condition | Number of results greater than 0 |
| Trigger mode | Once |
| Configured severity | High |
| Throttle | 10 minutes |
| Expiration | 24 hours |
| Permissions | Private |

The alert was enabled and successfully triggered during the second controlled simulation.

The High value is the configured detection severity. It is not, by itself, the analyst's assessment of the authorized test.

## 7. Detection Evidence and Investigation

### 7.1 Event 4688 — Process Creation

| Field | Observed value |
|---|---|
| Time | `2026-11-22 19:26:46.327` |
| Host | `DESKTOP-PPSKJ22` |
| User | `window` |
| Process | `powershell.exe` |
| Parent process | `powershell.exe` |
| Command-line parameter | `-NoProfile -EncodedCommand` |
| Detection | PowerShell Encoded Command Execution |
| Configured severity | High |

### 7.2 Event 4104 — Script Block Logging

| Field | Observed value |
|---|---|
| Time | `2026-11-22 19:26:46.882` |
| Host | `DESKTOP-PPSKJ22` |
| Event ID | 4104 |
| Script content | `Write-Output "SOC_LAB_ENCODED_TEST_2"` |
| Process ID | `6596` |
| Event Record ID | `1602` |

The events occurred approximately 555 milliseconds apart. Event 4688 recorded the encoded process command line, while Event 4104 recorded the harmless decoded script content.

The source evidence provided a Process ID for Event 4104 but did not provide the corresponding process ID from Event 4688. Therefore, the events are temporally consistent and support the same controlled test, but exact process-level correlation is not established by the recorded fields alone.

### 7.3 Investigation conclusions

The investigation established that:

1. The process was launched on the expected Windows lab host.
2. The executing account was `window`.
3. The process was `powershell.exe`.
4. The command line contained `-EncodedCommand`.
5. The nearby Event 4104 contained the expected test marker.
6. The decoded script was a harmless `Write-Output` command.
7. The scheduled Splunk alert triggered successfully.

**Classification:** Authorized lab security test.

**Analyst outcome:** No confirmed compromise based on the evidence examined.

The alert's configured High severity must not be confused with a confirmed high-severity security incident.

## 8. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell was used to execute the encoded command |

Base64 encoding is not encryption. Encoded PowerShell is not inherently malicious. Investigation should consider the user, host, process path, command content, parent process, script-block evidence, and surrounding activity.

## 9. Dashboard and Reporting

**Dashboard:** `Windows PowerShell Encoded Command Monitoring`

The dashboard contains four panels:

1. Encoded PowerShell Executions by User.
2. Recent Encoded PowerShell Process Events.
3. PowerShell Script Block Logging (4104).
4. Encoded PowerShell Activity Over Time.

The dashboard uses a 24-hour display window so that the controlled test events remain visible.

The 4104 panel is supporting investigation evidence. Script blocks containing Base64-related commands or encoded-command strings are not automatically malicious.

## 10. Final Validation

| Validation item | Recorded result |
|---|---|
| PowerShell Script Block Logging enabled | Verified |
| PowerShell Operational events collected | Verified |
| Process Creation auditing enabled | Verified |
| Command-line logging enabled | Verified |
| Event 4688 detected | Verified |
| Event 4104 observed | Verified |
| Detection SPL validated | Verified |
| Report saved | Verified |
| Scheduled alert enabled | Verified |
| Alert triggered | Confirmed |
| Dashboard created and saved | Confirmed |

## 11. Lessons Learned and Limitations

- Base64 encoding is not encryption.
- Encoded PowerShell commands are not automatically malicious.
- Event 4688 provides process execution and command-line evidence.
- Event 4104 can provide PowerShell script-block content.
- Process-level correlation should use matching process identifiers when available; close timestamps alone are not conclusive.
- Filtering by process name makes the detection more specific to PowerShell.
- Detection severity and analyst incident assessment are different concepts.
- Scheduled detection must be validated with a fresh event inside its operational search window.
- The recorded Event 4104 process ID was not accompanied by a matching Event 4688 process ID in the source evidence.

**Screenshot evidence:** Add genuine screenshots of the 4688 detection result, 4104 script-block event, triggered alert, and dashboard if available. Do not create placeholder images and present them as evidence.

Suggested paths:

- `evidence/windows/windows-powershell-4688-detection.png`
- `evidence/windows/windows-powershell-4104-scriptblock.png`
- `evidence/windows/windows-powershell-alert.png`
- `evidence/windows/windows-powershell-dashboard.png`

---

**Stage outcome:** The controlled encoded PowerShell command was recorded in Event 4688, supporting script-block evidence was observed in Event 4104, the Splunk detection and scheduled alert were validated, and the dashboard was created and saved. The test was authorized and no compromise was confirmed by the evidence examined.
