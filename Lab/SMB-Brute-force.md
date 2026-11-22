# Windows SMB Brute-Force Detection and Investigation

## 1. Overview

This lab simulated repeated incorrect SMB password attempts against a Windows local account. The objective was to detect the failed logons in Splunk, validate a scheduled alert, and investigate the resulting activity.

| Metadata | Details |
|---|---|
| Scenario | Windows SMB password-guessing simulation |
| Date | 20 November 2026 |
| Source | Kali Linux — `192.168.64.6` |
| Target | Windows — `DESKTOP-PPSKJ22` (`192.168.64.8`) |
| Target account | `soc_lab` |
| SMB share | `SOC-Lab` |
| Splunk index used in the documented search | `*` |
| Windows event | Security Event ID `4625` |

This was an authorized lab simulation. The collected evidence did not establish a successful compromise.

## 2. Attack Simulation

A dedicated local account, `soc_lab`, and an SMB share named `SOC-Lab` were used. A successful baseline SMB login had previously confirmed that the account and share were reachable.

Four incorrect-password attempts were entered manually from Kali:

```bash
smbclient //192.168.64.8/SOC-Lab -U 'DESKTOP-PPSKJ22\soc_lab'
```

Windows recorded four failed logons:

| Date and time (IST) | Event ID |
|---|---:|
| 20 November 2026, 15:14:10 | 4625 |
| 20 November 2026, 15:14:15 | 4625 |
| 20 November 2026, 15:14:20 | 4625 |
| 20 November 2026, 15:14:41 | 4625 |

The events identified `soc_lab` as the target account and `192.168.64.6` as the source IP. The source workstation was identified as `KALI`.

## 3. Detection Engineering

### 3.1 Confirm log ingestion

The following search was used to check whether Windows events containing the target account were available in Splunk:

```spl
index=* "soc_lab" earliest=-30m
```

The returned events contained the account name and raw Windows XML data.

### 3.2 Extract fields from raw XML

The required fields were not populated by `spath` during testing. Regular expressions (`rex`) were therefore used to extract them directly from `_raw`.

```spl
index=* "soc_lab" earliest=-30m
| rex field=_raw "Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "Name='IpAddress'>(?<source_ip>[^<]+)"
| rex field=_raw "Name='WorkstationName'>(?<source_workstation>[^<]+)"
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
```

Extracted fields:

- `target_user`: Account targeted by the authentication attempt.
- `source_ip`: IP address associated with the attempt.
- `source_workstation`: Source workstation name.
- `event_id`: Windows Security event ID.

### 3.3 Filter failed logons and group events

Event ID `4625` represents a failed logon. The search retained these events and grouped them into fixed five-minute buckets by source IP and target account.

```spl
| search event_id=4625
| eval event_time=_time
| bin _time span=5m
| stats count as failed_attempts
    min(event_time) as first_seen
    max(event_time) as last_seen
    values(host) as target_host
    values(source_workstation) as source_workstation
    by _time source_ip target_user
| where failed_attempts >= 4
```

The grouping keeps different source IPs and target accounts separate. The threshold of four failures was used for this lab validation; it is not a universal production threshold.

### 3.4 Complete detection SPL

This is the complete detection search documented as successfully validated in the lab:

```spl
index=* "soc_lab" earliest=-30m
| rex field=_raw "Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "Name='IpAddress'>(?<source_ip>[^<]+)"
| rex field=_raw "Name='WorkstationName'>(?<source_workstation>[^<]+)"
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id=4625
| eval event_time=_time
| bin _time span=5m
| stats count as failed_attempts
    min(event_time) as first_seen
    max(event_time) as last_seen
    values(host) as target_host
    values(source_workstation) as source_workstation
    by _time source_ip target_user
| where failed_attempts >= 4
| sort -_time
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen target_host source_ip source_workstation target_user failed_attempts
```

The search:

1. Reads matching Windows events.
2. Extracts the required fields from raw XML.
3. Retains failed logons (Event ID `4625`).
4. Groups failures into fixed five-minute buckets by source IP and target account.
5. Returns groups containing at least four failures.
6. Displays the first and last observed event times and other investigation fields.

### 3.5 Observed detection result

The first explicitly documented four-failure detection result was:

| First seen | Last seen | Target host | Source IP | Workstation | Account | Failures |
|---|---|---|---|---|---|---:|
| 2026-11-20 13:25:24 | 2026-11-20 13:25:42 | `DESKTOP-PPSKJ22` | `192.168.64.6` | `KALI` | `soc_lab` | 4 |

This result is from an earlier recorded test. The four failures at 15:14 were a later controlled test. The scheduled alert was subsequently observed triggering at 15:15:01 IST.

### 3.6 Threshold validation

| Test | Observed result | Outcome |
|---|---|---|
| One failure from one source | No detection result | Passed |
| Three failures from one source | No detection result | Passed |
| Four failures from one source | Detection result | Passed |
| Two failures from Kali and two from Ubuntu in the same five-minute bucket | Two separate groups; neither reached the threshold | Passed |

The source-grouping test used Kali (`192.168.64.6`) and Ubuntu (`192.168.64.5`). Their failures were counted separately.

## 4. Scheduled Alert

| Setting | Configured value |
|---|---|
| Alert name | `Windows - SMB Brute Force Detection` |
| Alert type | Scheduled |
| Schedule | Every five minutes (`*/5 * * * *`) |
| Search window | Last 15 minutes, as recorded in the alert configuration |
| Trigger condition | Number of results greater than 0 |
| Trigger setting | Once |
| Throttling | 15 minutes |
| Action | Add to Triggered Alerts |
| Permissions | Private |
| Configured severity | Medium |

The alert was saved and enabled. A triggered-alert record was observed at `2026-11-20 15:15:01 IST`. The alert results were opened and the expected results were confirmed.

**Search-window note:** The documented SPL above contains `earliest=-30m`, while the alert configuration records a 15-minute search window. Verify the saved alert's actual SPL and time-range settings in Splunk before treating these as identical configurations.

## 5. MITRE ATT&CK Mapping

| Field | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Sub-technique | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Justification:** The simulation generated repeated incorrect password attempts against one account over SMB. The Windows 4625 events and Splunk results showed repeated failures against `soc_lab` from the same source. This behavior is consistent with password guessing.

The test did not demonstrate password cracking, password spraying, credential stuffing, or successful compromise.

## 6. SOC Investigation and Assessment

The investigation identified:

- Target host: `DESKTOP-PPSKJ22`.
- Target account: `soc_lab`.
- Source IP: `192.168.64.6`.
- Source workstation: `KALI`.
- Four failed logons at 15:14:10, 15:14:15, 15:14:20, and 15:14:41 on 20 November 2026.
- The Windows event evidence identified Logon Type `3` (network logon) and NTLM authentication for the controlled SMB activity.

A 24-hour successful-logon search returned two earlier Event ID `4624` records: one from Kali at 12:57:41 and another from Ubuntu at 14:23:32. Both occurred before the 15:14 test.

The post-test search covering 15:14–15:25 returned the four failed logons and no Event ID `4624`. This finding applies only to the reviewed time window.

### Authentication verification search

The following search was used to review successful and failed logons for `soc_lab`:

```spl
index=* "soc_lab" earliest=-30m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "Name='IpAddress'>(?<source_ip>[^<]+)"
| search event_id=4624 OR event_id=4625
| table _time host event_id target_user source_ip
| sort _time
```

The `soc_lab` account was checked and reported `Disabled=False` and `Lockout=False`.

**Assessment:**

- Configured alert severity: Medium.
- Analyst assessment: Low.
- Classification: Authorized lab activity; no confirmed compromise in the reviewed evidence.

The alert severity describes the detection configuration. It does not establish that the lab activity was malicious.

## 7. Response and Remediation

### Actions and checks performed

- Reviewed the post-test window for successful logons. No Event ID `4624` was observed in that window.
- Did not disable the lab account or permanently block the authorized Kali VM.
- Verified that `soc_lab` was enabled and not locked.
- Checked that the `SOC-Lab` share and its access permissions remained available after testing.

### Required follow-up

Windows Firewall was disabled across the Domain, Private, and Public profiles at the time of the recorded test. Re-enable it and replace broad profile disablement with narrowly scoped rules for the isolated lab network and required services.

The observed account lockout policy had a threshold of 10 attempts, a 10-minute lockout duration, and a 10-minute observation window. Review this policy and use a strong, unique password for the lab account.

Firewall restoration is a required follow-up; it is not documented as a completed action.

## 8. Dashboard and Evidence

The four-panel dashboard was created and confirmed visible in View mode.

The original document identifies these screenshot paths:

- `evidence/windows/windows-bruteforce-detection.png`
- `evidence/windows/windows-bruteforce-investigation.png`

The screenshots were not supplied with the document. Add genuine screenshots from Splunk before publishing the corresponding image references.

## 9. Limitations and Lessons Learned

- The documented search uses `index=*`. Confirm the intended index, source, and sourcetype before using it as a production detection.
- Raw XML fields were extracted with `rex` because `spath` did not populate the required fields during testing.
- `bin _time span=5m` creates fixed five-minute buckets. It is not a rolling five-minute window.
- Four failures is a lab-specific threshold, not a universal production threshold.
- The documented SPL uses a 30-minute search range, while the alert configuration records a 15-minute search window. Verify the saved alert settings.
- Splunk displayed a trial-license warning that scheduled searches would not run after the Enterprise Trial License expired.

The exercise demonstrated how repeated SMB authentication failures can be detected through Windows Security events and investigated in Splunk. It also highlighted the importance of validating field extraction, time windows, thresholds, and alert configuration.

**Outcome:** The controlled SMB password-guessing activity was detected, the scheduled alert triggered, the available authentication evidence was investigated, and the behavior was mapped to MITRE ATT&CK T1110.001. The four-panel dashboard was created and confirmed visible in View mode. Findings are limited to the events and time windows reviewed.