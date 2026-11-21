# Windows SMB Brute-Force Detection and Investigation

## 01. Title & Incident Metadata

**Windows SMB Brute-Force Detection and Investigation**

| Metadata | Details |
|---|---|
| Project | SOC Detection, Investigation & Incident Response Platform |
| Attack scenario | Controlled Windows SMB password-guessing simulation |
| Date | 20 November 2026 |
| Attacker / source | Kali Linux — `192.168.64.6` |
| Target | Windows — `DESKTOP-PPSKJ22` (`192.168.64.8`) |
| Target account / outcome | `soc_lab` — four failed attempts observed; no successful login observed in the immediate post-test review window |

## 02. Executive Summary

- A controlled SMB authentication test was performed from the Kali Linux lab VM against the Windows `soc_lab` account.
- Windows recorded the failed network logons as Event ID `4625`
- Splunk correlated four failures from the same source IP and same account then triggered the scheduled detection alert.
- The investigation found no Event ID `4624` in the reviewed 15:14–15:25 window.
- no successful compromise was established by the collected evidence.

## 03. Attack Simulation – Red Team Context

- A dedicated local account `soc_lab` and a lab share named `SOC-Lab` were used.
- A successful baseline SMB login had previously confirmed that the account and share were reachable.
- The test was run from the Kali VM (`192.168.64.6`) against the Windows VM (`192.168.64.8`) over SMB.
- Four incorrect-password attempts were made manually.

- Command used from Kali.(the password was entered intentionally wrong)

```bash
smbclient //192.168.64.8/SOC-Lab -U 'DESKTOP-PPSKJ22\soc_lab'
```

The four failed attempts were observed on Windows at

| Time (20 November 2026, IST) | Windows event |
|---|---|
| 15:14:10 | Event ID 4625 |
| 15:14:15 | Event ID 4625 |
| 15:14:20 | Event ID 4625 |
| 15:14:41 | Event ID 4625 |

- All four events identified `soc_lab` as the target account and `192.168.64.6` as the source IP. 
- The source workstation was reported as `KALI` in the Windows event evidence.

## 04. Detection Engineering – Splunk SPL

####  1. Confirm Logs Are Arriving

```spl
index=* "soc_lab" earliest=-30m
```

- Windows event data were arriving.
- The target account "soc_lab" appears in the events.
- Raw XML contains information such as Event ID, target username and IP address.

#### 2. Extract Fields from Raw XML
```spl
index=* "soc_lab" earliest=-30m
|rex field=_raw "Name='TargetUserName'>(?<target_user>[^<]+)"
|rex field=_raw "Name='IpAddress'>(?<source_ip>[^<]+)"
|rex field=_raw "Name='WorkstationName'>(?<source_workstation>[^<]+)"
|rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
```

- The required fields were not populated by "spath" for this raw XML format during testing. 
- Therefore "rex" was used to extract the values directly from "_raw".
- The rex : command creates searchable fields from the raw event. It does not modify the original Windows event.

target_user : Identifies the account being targeted.
source_ip : Identifies the IP address generating the authentication attempt.
source_workstation : Identifies the source computer name.
event_id : Identifies which Windows security event occurred.



#### 3: Filter Only Failed Logons
```
| search event_id=4625
```

- Windows records different authentication outcomes:
4624 — Successful logon.
4625 — Failed logon.

- For this detection we only need failed authentication attempts.
-  event_id=4625 removes unrelated successful logon events from the detection calculation.

#### 4. Preserve Exact Timestamps and Create Time Buckets
```
| eval event_time=_time
| bin _time span=5m
```

- We need to identify repeated failures within a short period.
 eval event_time=_time (saves the original event timestamp)
 bin _time span=5m (groups events into fixed five-minute time buckets)

##### 5. Aggregate Failures and Apply the Detection Threshold
```
| stats count as failed_attempts
    min(event_time) as first_seen
    max(event_time) as last_seen
    values(host) as target_host
    values(source_workstation) as source_workstation
    by _time source_ip target_user
| where failed_attempts >= 4
```

This is the main detection logic.

- The stats command groups events using three fields
_time (Groups events into the same five-minute bucket)
 source_ip (Separates attempts coming from different source IPs)
 target_user (Separates attempts against different accounts.

Other calculations:

- "count as failed_attempts" counts failed logons in each group.
- "min(event_time) as first_seen" identifies the first actual attempt.
- "max(event_time) as last_seen" identifies the last actual attempt.
- "values(host) as target_host" records the Windows target hostname.
- "values(source_workstation) as source_workstation" records the source workstation name.
- "where failed_attempts >= 4" keeps only groups containing four or more failures.


- Why group by source IP and target account?
Without these fields, failures from different computers or against different accounts could be combined into one count. Grouping ensures that the detection evaluates each source-and-account combination separately.

#### 6. Format Timestamps and Display the Final Results
```
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen target_host source_ip source_workstation target_user failed_attempts
| sort -_time
```
- "strftime()" converts epoch timestamps into readable date and time values.
- "table" displays only the fields needed by a SOC analyst.
- "sort -_time" sorts results by time in descending order when "_time" is retained.

Note: Because the final "table" above does not retain "_time", use the following corrected final ordering if you want to sort the displayed detection results by the original bucket time:

| sort -_time
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen target_host source_ip source_workstation target_user failed_attempts

#### 7. Complete Detection SPL

This is the complete query that was executed and successfully validated in the lab:
```
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
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen target_host source_ip source_workstation target_user failed_attempts
```

### What the search does

- Extracts the target account, source IP, source workstation, and Windows event ID from the raw XML event.
- Keeps Event ID `4625`, which represents a failed logon.
- Groups events into fixed five-minute time buckets by source IP and target account.
- Returns a detection when a group contains at least four failures.

### Observed detection result

| First seen | Last seen | Target host | Source IP | Workstation | Account | Failures |
|---|---|---|---|---|---|---:|
| 2026-11-20 13:25:24 | 2026-11-20 13:25:42 | `DESKTOP-PPSKJ22` | `192.168.64.6` | `KALI` | `soc_lab` | 4 |

The table above is the first four-failure detection result that was explicitly verified in Splunk. A later controlled four-failure test also triggered the scheduled alert.

### Tuning checks performed

| Test | Observed result | Expected result | Outcome |
|---|---|---|---|
| One failure from one source | No detection result | No alert threshold reached | Passed |
| Three failures from one source | No detection result | No alert threshold reached | Passed |
| Four failures from one source | Detection result | Threshold reached | Passed |
| Two failures from Kali and two from Ubuntu in the same five-minute bucket | Two separate source groups, each with two failures; no detection result | Do not combine different source IPs | Passed |

The source-grouping test used Kali `192.168.64.6` and Ubuntu `192.168.64.5`. Splunk grouped them separately because `source_ip` is part of the aggregation.

### Scheduled alert configuration

| Setting | Configured value |
|---|---|
| Alert name | `Windows - SMB Brute Force Detection` |
| Alert type | Scheduled |
| Schedule | Every five minutes (`*/5 * * * *`) |
| Search window | Last 15 minutes (`earliest=-15m` in the saved search) |
| Trigger condition | Number of results greater than 0 |
| Trigger setting | Once |
| Throttling | 15 minutes |
| Action | Add to Triggered Alerts |
| Permissions | Private |
| Configured alert severity | Medium |

The alert was saved and enabled. A triggered-alert record was observed at `2026-11-20 15:15:01 IST`, and the user opened the alert results and confirmed the expected results were present.

### Detection limitations

- `index=*` was used because the exact project index had not been confirmed in the evidence available for this exercise. The actual index, sourcetype, and source values should be identified before optimizing the search.
- The raw XML fields were extracted with `rex`; `spath` did not populate the required fields for this event format in the test.
- `bin _time span=5m` creates fixed five-minute buckets. It is not a sliding five-minute window.
- The threshold of four failures is a lab validation threshold, not a universal production threshold.
- Splunk displayed a trial-license warning that scheduled searches would not run after the Splunk Enterprise Trial License expires.

**Screenshot evidence to add:** Save a genuine cropped screenshot of the successful SPL result as `evidence/windows/windows-bruteforce-detection.png`, then include it here:

```markdown
![Splunk Windows SMB brute-force detection result](../../evidence/windows/windows-bruteforce-detection.png)
```

The screenshot file was not supplied with this document request; do not create a substitute or treat this reference as an existing file.

## 05. MITRE ATT&CK Mapping

| Field | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Sub-technique | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Justification:** The lab generated repeated incorrect password attempts against one account over SMB. The Windows 4625 events and Splunk grouping showed repeated failures against `soc_lab` from the same source. This behavior is consistent with password guessing. The test does not demonstrate password cracking, password spraying, credential stuffing, or a successful compromise.

## 06. SOC Investigation & Triage

### Findings

- The target was `DESKTOP-PPSKJ22`; the account was `soc_lab`; the source was Kali at `192.168.64.6`.
- Four Event ID `4625` events were observed at 15:14:10, 15:14:15, 15:14:20, and 15:14:41 on 20 November 2026.
- The Windows event evidence identified Logon Type `3` (network logon) for the earlier controlled failed SMB authentication test, with source workstation `KALI` and NTLM authentication. The four later events were confirmed as 4625 failures from the same source and account.
- A 24-hour successful-logon search returned two earlier Event ID `4624` records: Kali at 12:57:41 and Ubuntu at 14:23:32. Both occurred before the 15:14 test.
- The 15:14–15:25 post-test search returned the four 4625 failures and no 4624 record. This means no successful logon was observed in that reviewed window; it does not prove that no successful logon occurred at any other time.

### Verification search: failed and successful logons

This search was used to review Event IDs `4624` and `4625` for the `soc_lab` account:

```spl
index=* "soc_lab" earliest=-30m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| rex field=_raw "Name='TargetUserName'>(?<target_user>[^<]+)"
| rex field=_raw "Name='IpAddress'>(?<source_ip>[^<]+)"
| search event_id=4624 OR event_id=4625
| table _time host event_id target_user source_ip
| sort _time
```

### Alert and incident assessment

- The scheduled Splunk alert triggered at `15:15:01 IST`.
- The alert was configured with Medium severity; the analyst assessment for this controlled lab event was Low.
- No successful authentication was observed in the immediate post-test window, and no evidence of compromise was identified in the reviewed data.
- The `soc_lab` account was checked and reported `Disabled=False` and `Lockout=False`.

**Screenshot evidence to add:** Save a genuine cropped screenshot of the investigation search and its results as `evidence/windows/windows-bruteforce-investigation.png`, then include it here:

```markdown
![Splunk Windows authentication investigation](../../evidence/windows/windows-bruteforce-investigation.png)
```

The screenshot file was not supplied with this document request; add the real screenshot from Splunk before publishing.

## 07. Containment & Remediation

### Immediate response actions

- Reviewed the post-test authentication window for Event ID `4624`; no successful logon was observed in that window, so the lab account was not disabled and the authorized Kali VM was not permanently blocked.
- Verified that `soc_lab` was enabled and not locked, and checked that the `SOC-Lab` SMB share and its access permissions remained available after testing.

### Permanent hardening measures

- Re-enable Windows Firewall after the required lab connectivity tests and replace the broad all-profile disablement with narrowly scoped rules for the isolated lab network and required services. At the time of the recorded test, Windows Firewall had been disabled across Domain, Private, and Public profiles; restoration is a required follow-up, not a completed action.
- Review the Windows account lockout policy and ensure the lab account uses a strong, unique password. The observed local policy during preparation had a lockout threshold of 10 attempts, a 10-minute lockout duration, and a 10-minute observation window; repeated testing can therefore lock the account.

## 08. Lessons Learned & Visibility Gaps

The Windows event XML did not populate the required fields through `spath`, so the fields used by the detection were extracted with `rex` and verified against the raw events. The search still uses broad index selection and fixed five-minute buckets, so its index/sourcetype and time-window logic should be refined before treating it as production-ready.

---

**Stage outcome:** The controlled Windows SMB password-guessing simulation was detected, the scheduled Splunk alert was triggered, the available authentication evidence was investigated, the behavior was mapped to MITRE ATT&CK T1110.001, and the four-panel dashboard was created and confirmed visible in View mode. The findings are limited to the events and test window recorded above.
