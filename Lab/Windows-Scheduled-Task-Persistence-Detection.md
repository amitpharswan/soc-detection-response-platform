# Stage 6 — Windows Scheduled Task Persistence Detection and Investigation

## 1. Overview

This lab examined how scheduled tasks can be used to maintain persistence on Windows and how a SOC analyst can monitor task creation, registration, and execution.

Three harmless scheduled tasks were created for controlled testing. Windows Security and Task Scheduler Operational events were collected in Splunk. Creation detections and scheduled alerts were validated, task execution was reviewed, and all temporary tasks and marker files were removed.

| Metadata | Details |
|---|---|
| Scenario | Windows scheduled task creation and execution monitoring |
| Endpoint | Windows 11 Home ARM |
| Hostname | `DESKTOP-PPSKJ22` |
| SIEM | Splunk Enterprise |
| Forwarder | Splunk Universal Forwarder |
| Index | `main` |
| Security source | `WinEventLog:Security` |
| Task Scheduler source | `Microsoft-Windows-TaskScheduler/Operational` |
| Authorized test account | `window` |
| Outcome | Detection, alerting, investigation, dashboard, and cleanup reported complete |

This was an authorized lab exercise. The tasks used harmless commands to write marker text to temporary files. They did not download files, modify security settings, or execute malicious commands.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Windows endpoint | Windows 11 Home ARM |
| Hostname | `DESKTOP-PPSKJ22` |
| SIEM | Splunk Enterprise |
| Log forwarder | Splunk Universal Forwarder |
| Splunk index | `main` |
| Windows Security log | `WinEventLog:Security` |
| Task Scheduler log | `Microsoft-Windows-TaskScheduler/Operational` |
| Account used for testing | `window` |

## 3. Windows Logging and Splunk Configuration

### 3.1 Enable Task Scheduler Operational logging

The Task Scheduler Operational event channel was enabled.

### 3.2 Enable Security auditing

Successful auditing for **Other Object Access Events** was enabled to collect scheduled-task creation evidence in the Windows Security log.

### 3.3 Configure Universal Forwarder collection

The Windows Universal Forwarder was configured to collect:

- Windows Security events.
- `Microsoft-Windows-TaskScheduler/Operational` events.

Both event sources were verified as arriving in Splunk under index `main`.

### 3.4 Confirm event ingestion

Use these searches to confirm that the two sources are available. They are validation searches; they are not represented as the exact saved report or alert SPL from the original lab.

**Windows Security events:**

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Security"
earliest=-24h
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id="4698"
| table _time host sourcetype event_id _raw
| sort -_time
```

**Task Scheduler Operational events:**

```spl
index=main host="DESKTOP-PPSKJ22"
source="WinEventLog:Microsoft-Windows-TaskScheduler/Operational"
earliest=-24h
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id="106" OR event_id="100" OR event_id="200" OR event_id="201" OR event_id="102"
| table _time host sourcetype event_id _raw
| sort -_time
```

Review the raw XML before building field extractions or alert logic. Event field names and XML content should be based on the actual events received from the endpoint.

## 4. Controlled Lab Simulation

Three harmless scheduled tasks were created:

1. `SOC-LAB-Persistence-Test`
2. `SOC-LAB-Persistence-Alert-Test`
3. `SOC-LAB-4698-Alert-Test`

The tasks used `cmd.exe` to write harmless marker text to temporary files.

The tasks were configured with limited privileges. They did not download files, modify security settings, or execute malicious commands.

Two successful executions of `SOC-LAB-Persistence-Test` were verified in the Windows event evidence. Both executions completed with return code `0`.

## 5. Windows Events Used

The source document listed the following event IDs for task creation, registration, and execution monitoring.

| Event ID | Description recorded in the lab | Use in investigation |
|---|---|---|
| 4698 | Scheduled task created — Security log | Identify task creation and creator details |
| 106 | Scheduled task registered — Task Scheduler Operational | Additional task-registration evidence |
| 140 | Scheduled task updated | Identify task changes |
| 325 | Task instance queued | Task lifecycle context |
| 110 | Task launched | Task lifecycle context |
| 129 | Task action process launched | Action process context |
| 100 | Task started | Execution lifecycle |
| 200 | Task action started | Action execution |
| 201 | Task action completed | Action completion and result |
| 102 | Task finished | Task completion |

**Event interpretation note:** The table preserves the event IDs and descriptions recorded in the lab notes. Before publishing a production detection, validate each event ID against the raw event message and the Windows version in use. Do not rely on an event ID alone when its message or task context is unavailable.

## 6. Detection Results and Monitoring

### 6.1 Scheduled task creation — Security Event 4698

- Source: Windows Security log.
- Event ID: `4698`.
- The lab detection identified scheduled task creation.
- The recorded extracted information included the creating account, task name, and event timestamp.

### 6.2 Scheduled task registration — Task Scheduler Event 106

- Source: Task Scheduler Operational log.
- Event ID: `106`.
- The lab detection identified task registration.
- The recorded extracted information included task name, user context, and event timestamp.

### 6.3 Scheduled task execution lifecycle

The lab monitored these events:

- `100` — Task started.
- `200` — Action started.
- `201` — Action completed.
- `102` — Task finished.

Two successful executions of `SOC-LAB-Persistence-Test` were verified. Both executions completed with return code `0` in the Windows event evidence.

A task-start event does not, by itself, prove that its action completed successfully. Review the relevant action-start, action-completion, task-finished events, and return code where available.

### 6.4 Detection SPL documentation gap

The original Stage 6 notes report that the detections and reports were created, but they do not contain the actual saved SPL searches, field-extraction expressions, or report definitions.

For that reason, this document does not invent or label a reconstructed query as the exact operational detection used in the lab.

Before treating the detection engineering documentation as complete, add the exact saved SPL for:

1. Security Event 4698 task creation detection.
2. Task Scheduler Event 106 registration detection.
3. Task execution lifecycle monitoring using the recorded event IDs.
4. Any field extraction used for task name, creator, user context, action, and return code.

The two validation searches in Section 3 confirm event availability and provide raw events for inspection. They are not substitutes for the missing saved detection searches.

## 7. Splunk Reports and Alerts

### 7.1 Reports created

The following reports were recorded as created:

1. `Windows Scheduled Task Creation Detection`
2. `Windows Scheduled Task Creation - Security Event 4698`
3. `Windows Scheduled Task Execution Monitoring`

The source notes do not include the saved SPL or report schedules for these reports.

### 7.2 Alerts created and enabled

The following alerts were recorded as created and enabled:

1. `Windows - Scheduled Task Creation Detection`
2. `Windows - Scheduled Task Creation (4698)`

Both alerts were successfully triggered during controlled lab testing.

**Review required:** The two alert names may represent separate detections, such as a Task Scheduler registration event and a Security 4698 event, or they may overlap. The original notes do not include their SPL definitions, so their exact differences cannot be confirmed here. Compare the saved searches in Splunk. If both alerts detect the same event and behavior, consolidate them or clearly document their distinct data sources and purposes.

The original notes do not specify the alert schedule, search time range, trigger condition, throttle, severity, or permissions. Those settings should be copied from the saved alert configurations rather than inferred.

## 8. SOC Investigation and Findings

The controlled tests were performed using the authorized Windows account `window`.

The evidence recorded in the lab confirmed:

- Windows generated Security Event `4698`.
- Windows generated Task Scheduler Operational Event `106`.
- Splunk received both event sources.
- Both scheduled-task creation detections returned the expected results.
- Both scheduled alerts triggered.
- Task execution events `100`, `200`, `201`, and `102` were collected and investigated.
- Two executions of `SOC-LAB-Persistence-Test` completed with return code `0`.

These events represent authorized lab activity, not a confirmed security compromise.

### Investigation checklist

For a real scheduled-task alert, review:

- Task name and task path.
- Creating account and logon context.
- Task registration and creation timestamps.
- Task action, executable path, and arguments.
- Trigger schedule and run frequency.
- Whether the task runs as SYSTEM, an administrator, or a standard user.
- Parent process and action process, where available.
- Task execution result and return code.
- Whether the task and its action are approved and expected.
- Related account creation, group changes, process execution, and network activity.

The checklist is recommended investigation guidance. The original lab notes do not state that every item was collected or examined during this test.

## 9. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled tasks were created and executed in the controlled lab |

Scheduled tasks can be used for persistence, but task creation is not automatically malicious. The analyst must inspect the task's creator, action, execution context, trigger, and surrounding activity.

## 10. Dashboard and Reporting

**Dashboard:** `Windows Scheduled Task Persistence Monitoring`

**Permissions:** Private.

The dashboard contains four panels:

1. Scheduled Task Creation Events (4698).
2. Scheduled Task Registration Events (106).
3. Scheduled Task Execution Lifecycle.
4. Scheduled Task Creation by User.

The dashboard was reported as created. The original notes do not include panel SPL, dashboard time range, or screenshots. Add the exact saved searches and genuine screenshots if these are required for reproducibility.

Suggested screenshot paths:

- `evidence/windows/windows-scheduled-task-4698.png`
- `evidence/windows/windows-scheduled-task-106.png`
- `evidence/windows/windows-scheduled-task-execution.png`
- `evidence/windows/windows-scheduled-task-dashboard.png`
- `evidence/windows/windows-scheduled-task-alerts.png`

Do not create placeholder screenshots and present them as evidence.

## 11. Cleanup and Validation

All three temporary scheduled tasks were removed:

- `SOC-LAB-Persistence-Test`
- `SOC-LAB-Persistence-Alert-Test`
- `SOC-LAB-4698-Alert-Test`

All three temporary marker files were removed.

Cleanup was verified:

- No `SOC-LAB-*` scheduled tasks remained.
- All three temporary marker files returned `Exists = False`.

This confirms that the temporary lab tasks and marker files were removed at the time of verification.

## 12. Lessons Learned and Documentation Gaps

- Scheduled tasks can be used for persistence on Windows systems.
- Security Event 4698 is useful for identifying scheduled-task creation.
- Task Scheduler Event 106 provides additional task-registration evidence.
- Events 100 and 200 provide execution lifecycle context.
- Events 201 and 102 help establish action and task completion.
- A task creation alert does not automatically mean malicious activity.
- Analysts should investigate the task name, creator, action, execution context, timing, and result.
- Both Windows Security and Task Scheduler Operational sources were received by Splunk.
- The original notes do not contain the actual saved SPL for the detections, reports, dashboard panels, or alert definitions. Those queries must be added from Splunk to make the work reproducible.
- The two scheduled-task creation alerts should be compared to confirm that they serve distinct purposes and do not duplicate the same detection.

## 13. Stage Outcome

**Stage 6: Completed — with a documentation gap.**

Creation detection, execution monitoring, alert validation, investigation, dashboard development, and cleanup were reported as completed in the lab notes. All three temporary tasks and marker files were removed and cleanup was verified.

The actual saved SPL for the detection searches, reports, and dashboard panels was not included in the original source document. Add those exact queries and verify the two alert definitions before considering the detection documentation fully reproducible.
