# Linux SSH Brute-Force Detection and Investigation

## 1. Overview

This lab simulated repeated incorrect SSH password attempts against a Linux account. The objective was to detect the failed logons in Splunk, validate a scheduled alert, and investigate the resulting activity.

| Metadata | Details |
|---|---|
| Scenario | Linux SSH password-guessing simulation |
| Date | 22 November 2026 |
| Source | Kali Linux — `192.168.64.6` |
| Target | Ubuntu Linux — `amit-QEMU-Virtual-Machine` (`192.168.64.5`) |
| Target account | `victim` |
| Splunk index | `main` |
| Log source | `/var/log/auth.log` |
| Sourcetype | `auth-2` |

This was an authorized lab simulation. No successful SSH authentication was identified in the reviewed investigation window.

## 2. Lab Setup and Attack Simulation

### Lab setup

- Kali Linux was used as the source VM.
- Ubuntu Linux was used as the SSH target.
- The target account was `victim`.
- SSH was running on Ubuntu and listening on TCP port `22`.
- Connectivity was verified from Kali:
  - Ping to `192.168.64.5` succeeded.
  - `nc -vz 192.168.64.5 22` confirmed that the SSH port was reachable.
- The Ubuntu Universal Forwarder service account, `splunkfwd`, was added to the `adm` group so it could read `/var/log/auth.log`.
- The Universal Forwarder was configured to send events to the Mac Splunk receiver at `10.244.150.12:9997`.

### Historical test and recovery

A test generated six failed password events at approximately 08:54 on 22 November 2026.

These events were not present in the original forwarded source when first searched. They were recovered from Ubuntu and ingested separately using a one-shot input from `/tmp/ssh-bruteforce-recovery.log` with sourcetype `auth-2`.

They must not be described as events that were originally forwarded live from `/var/log/auth.log`. The reason the original monitor did not forward those historical events at the time was not established.

| Time (22 November 2026, IST) | Target account | Source IP |
|---|---|---|
| 08:54:02 | `victim` | `192.168.64.6` |
| 08:54:11 | `victim` | `192.168.64.6` |
| 08:54:15 | `victim` | `192.168.64.6` |
| 08:54:44 | `victim` | `192.168.64.6` |
| 08:54:48 | `victim` | `192.168.64.6` |
| 08:54:53 | `victim` | `192.168.64.6` |

### Live forwarding verification

A marker generated with the following command appeared in Splunk from the normal `/var/log/auth.log` source:

```bash
logger -p auth.notice "SOC SSH forwarding test"
```

This confirmed that the normal authentication log forwarding path was working at the time of the check.

### Fresh controlled tests

| Test time (22 November 2026, IST) | Failed attempts | Observed result |
|---|---:|---|
| 09:31:23–09:31:46 | 5 | Detection result returned with 5 failures |
| 09:33:47–09:33:56 | 3 | Isolated search returned no detection result |
| 09:31–09:33 combined rolling 10-minute search | 8 | Rolling search combined both test runs |
| 09:50:37–09:51:06 | 6 | Detection result returned with 6 failures |

The six failures in the 09:50 test were recorded as follows:

| Time | SSH source port |
|---|---:|
| 09:50:37.075 | 34380 |
| 09:50:41.751 | 34380 |
| 09:50:46.371 | 34380 |
| 09:50:55.384 | 50264 |
| 09:51:00.254 | 50264 |
| 09:51:06.959 | 50264 |

All six events identified source IP `192.168.64.6` and target account `victim`.

## 3. Detection Engineering

### 3.1 Confirm log ingestion

```spl
index=main host="amit-QEMU-Virtual-Machine" source="/var/log/auth.log" earliest=-30m
```

This search checks whether events from the normal forwarded Ubuntu authentication log are available in Splunk.

### 3.2 Find failed SSH password events

```spl
index=main host="amit-QEMU-Virtual-Machine" source="/var/log/auth.log" earliest=-30m
"Failed password"
| table _time host source sourcetype _raw
| sort _time
```

The search filters SSH password failure messages and displays the raw event for inspection.

### 3.3 Extract fields

```spl
index=main host="amit-QEMU-Virtual-Machine" source="/var/log/auth.log" earliest=-30m
"Failed password"
| rex field=_raw "Failed password for (?<target_user>\S+) from (?<source_ip>\d+\.\d+\.\d+\.\d+) port (?<source_port>\d+)"
| table _time target_user source_ip source_port _raw
| sort _time
```

The `rex` command extracts fields from the raw SSH message.

| Field | Purpose |
|---|---|
| `target_user` | Account being targeted |
| `source_ip` | System generating the failed attempts |
| `source_port` | Client-side TCP source port for the SSH connection |

### 3.4 Complete operational detection SPL

The following search was used for the live SSH brute-force detection and scheduled alert:

```spl
index=main host="amit-QEMU-Virtual-Machine" source="/var/log/auth.log" earliest=-10m
"Failed password"
| rex field=_raw "Failed password for (?<target_user>\S+) from (?<source_ip>\d+\.\d+\.\d+\.\d+) port (?<source_port>\d+)"
| stats
    count as failed_attempts
    min(_time) as first_seen
    max(_time) as last_seen
    values(source_port) as source_ports
    by source_ip target_user
| where failed_attempts >= 5
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen last_seen source_ip target_user source_ports failed_attempts
```

The search:
1. Searches the normal forwarded Ubuntu authentication log in `main`.
2. Filters failed SSH password events.
3. Extracts the target account, source IP, and source port.
4. Counts failures by source IP and target account over the last ten minutes.
5. Returns a result when the count reaches five or more.
6. Displays the first and last event times and the observed source ports.

The search uses a rolling ten-minute window. It does not create fixed ten-minute buckets and does not distinguish individual SSH sessions. Attempts from the same source and account can be combined if they fall within the search window.

### 3.5 Observed detection result

The scheduled alert's View Results page showed:

| First seen | Last seen | Source IP | Target account | Source ports | Failures |
|---|---|---|---|---|---:|
| 2026-11-22 09:50:37 | 2026-11-22 09:51:06 | `192.168.64.6` | `victim` | `34380`, `50264` | 6 |

### 3.6 Threshold validation

| Test | Search result | Expected behavior | Outcome |
|---|---|---|---|
| Five failures in the 09:31 test | Detection result with 5 | Meet threshold | Passed |
| Three failures in isolated 09:33 window | No result | Remain below threshold | Passed |
| Combined 09:31 and 09:33 rolling 10-minute search | 8 failures | Rolling window can include both runs | Observed |
| Six failures in the 09:50 test | Detection result with 6 | Meet threshold | Passed |

### 3.7 Scheduled alert configuration

| Setting | Configured value |
|---|---|
| Alert name | `Linux - SSH Brute Force Detection` |
| Alert type | Scheduled |
| Schedule | Every five minutes (`*/5 * * * *`) |
| Time range in alert editor | Last 15 minutes |
| SPL search window | Last 10 minutes (`earliest=-10m`) |
| Trigger condition | Number of results greater than 0 |
| Trigger setting | Once |
| Throttling | 10 minutes |
| Action | Add to Triggered Alerts |
| Permissions | Private |
| Configured severity | Medium |
| Expiration | 24 hours |

The alert was saved and enabled. A triggered-alert record was observed at `2026-11-22 09:55:00 IST`. The alert's View Results page showed the six-failure result listed above.

The alert editor's selected time range was Last 15 minutes, while the SPL itself restricted the search to the last ten minutes using `earliest=-10m`.

### Detection limitations

- The operational search is limited to `main`, the Ubuntu host, and `/var/log/auth.log`. It does not include the separately recovered historical file.
- The detection counts events, not unique SSH sessions. Source ports are displayed as context but are not part of the grouping key.
- The `earliest=-10m` condition is a rolling search window, not a fixed ten-minute bucket.
- The scheduled search runs every five minutes; it is not an instant notification for each failed attempt.
- The threshold of five failures is a lab validation threshold, not a universal production threshold.
- The alert editor's time range was Last 15 minutes, while the SPL restricted the search to ten minutes.
- The cause of the initial historical-event forwarding gap was not established.

**Screenshot evidence to add:** Save a genuine screenshot of the operational SPL result as `evidence/linux/linux-ssh-bruteforce-detection.png`.

```markdown
![Splunk Linux SSH brute-force detection result](../../evidence/linux/linux-ssh-bruteforce-detection.png)
```

The screenshot was not supplied with this document. Add the actual Splunk screenshot before publishing.

## 4. MITRE ATT&CK Mapping

| Field | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Sub-technique | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

**Justification:** The controlled test used repeated incorrect passwords against one account. Ubuntu recorded repeated `Failed password` events for `victim` from the same source IP. This behavior is consistent with password guessing. The test does not demonstrate password spraying, credential stuffing, password cracking, or successful compromise.

## 5. SOC Investigation and Triage

### Findings

- Target: Ubuntu `amit-QEMU-Virtual-Machine` (`192.168.64.5`).
- Source: Kali (`192.168.64.6`).
- Target account: `victim`.
- The fresh 09:50 test produced six failed SSH password events between `09:50:37.075` and `09:51:06.959`.
- The six events were split across two SSH sessions:
  - Process ID `5823`, source port `34380`: three failed password events.
  - Process ID `5831`, source port `50264`: three failed password events.
- Both SSH connections were recorded as closed during pre-authentication.
- A GDM authentication failure at `09:50:10` was a separate graphical-login event and was not included in the SSH failure count.
- At `09:51:35`, `victim` opened a local sudo session to run `grep` against `/var/log/auth.log`. This was local log-review activity, not an SSH authentication success.
- The reviewed `09:45–10:15` window contained no SSH `Accepted` event or SSH session-opening event.
- The account status check showed that a password was set and the account was not reported as locked.
- `who` returned no rows at the time of the check.
- The established SSH connection check returned no connection rows at the time of the check.

### Investigation timeline

| Time (22 November 2026, IST) | Event | Finding |
|---|---|---|
| 09:50:10 | GDM authentication failure | Separate graphical-login event |
| 09:50:35 | SSH PAM authentication failure | SSH authentication attempt from `192.168.64.6` |
| 09:50:37–09:50:46 | Three failed passwords | SSH process `5823`, source port `34380` |
| 09:50:47 | SSH connection closed | Closed during pre-authentication |
| 09:50:53 | SSH PAM authentication failure | Second SSH authentication session |
| 09:50:55–09:51:06 | Three failed passwords | SSH process `5831`, source port `50264` |
| 09:51:07 | SSH connection closed | Closed during pre-authentication |
| 09:51:35 | Local sudo session | `victim` ran a local log-inspection command |

### Investigation search

```spl
index=main host="amit-QEMU-Virtual-Machine" source="/var/log/auth.log"
earliest="11/22/2026:09:45:00" latest="11/22/2026:10:15:00"
("sshd-session" OR "sshd" OR "pam_unix")
| eval event_category=case(
    match(_raw,"Failed password"),"SSH Authentication Failure",
    match(_raw,"Accepted"),"SSH Authentication Success",
    match(_raw,"session opened"),"Local Session Opened",
    match(_raw,"session closed"),"Local Session Closed",
    true(),"Other SSH/PAM Activity"
)
| table _time event_category _raw
| sort _time
```

The search classifies events for review while retaining the raw event so the classification can be checked against the original evidence.

### Account status

The following command was run on Ubuntu:

```bash
sudo passwd -S victim
```

Observed output:

```text
victim P 2026-11-08 0 99999 7 -1
```

`P` indicates that a password is set and that the account was not reported as password-locked by this command. This output does not establish password strength or other account restrictions.

### Logged-in users

```bash
who
```

Observed output: no rows.

### Established SSH connections

```bash
sudo ss -tnp state established '( sport = :22 )'
```

Observed output: the command returned its column headings and no connection rows.

These checks describe the state at the time they were run. They do not prove that no session existed at another time.

### Effective SSH configuration

```bash
sudo sshd -T | grep -E '^(passwordauthentication|pubkeyauthentication|maxauthtries|permitrootlogin)'
```

Observed output:

```text
maxauthtries 6
permitrootlogin prohibit-password
pubkeyauthentication yes
passwordauthentication yes
```

- `passwordauthentication yes` means password-based SSH authentication is enabled.
- `pubkeyauthentication yes` means public-key authentication is enabled as well; it does not disable password authentication.
- `maxauthtries 6` limits authentication attempts per SSH connection. It does not stop attempts across multiple connections from the same source.
- `permitrootlogin prohibit-password` prevents root password login while allowing other root authentication methods permitted by the SSH configuration.

### Alert and incident assessment

- The scheduled alert record was observed at `09:55:00 IST`.
- The alert results showed six failed attempts from `192.168.64.6` against `victim`.
- Configured alert severity: Medium.
- Analyst assessment: Low.
- Classification: Authorized lab activity; no confirmed compromise in the reviewed evidence.

No successful SSH authentication was identified in the reviewed `09:45–10:15` window. No active logged-in user or established SSH connection was shown by the later host checks.

**Screenshot evidence to add:** Save genuine screenshots of the investigation timeline and alert results as:

- `evidence/linux/linux-ssh-investigation-timeline.png`
- `evidence/linux/linux-ssh-alert-results.png`

The screenshots were not supplied with this document. Add the actual screenshots before publishing.

## 6. Response and Remediation

### Actions performed

- Reviewed the authentication window for successful SSH authentication. No `Accepted` event was identified in the reviewed results.
- Confirmed that both test SSH connections closed during pre-authentication.
- Checked the account status; it was not reported as password-locked.
- Checked for logged-in users and established SSH connections; the later checks returned no rows.
- Did not lock the account or block the Kali source because this was an authorized lab test and the reviewed evidence did not establish compromise.

### Recommended hardening

- Consider disabling SSH password authentication after confirming that key-based access works and a recovery path is available.
- Keep public-key authentication enabled and protect private keys.
- Review `MaxAuthTries`; the observed value was `6`. Reducing it may limit attempts per connection, but it does not replace monitoring or rate limiting across connections.
- Consider a rate-limiting control such as Fail2ban where appropriate.
- Restrict SSH access to trusted source addresses when practical.
- Continue monitoring failed and successful SSH authentication events.
- Review local accounts and disable accounts that are no longer required.

No SSH configuration changes or account-locking actions were documented as completed during this investigation.

## 7. Lessons Learned and Visibility Gaps

- A marker generated with `logger` appeared in Splunk from `/var/log/auth.log`, confirming that the normal forwarding path was working at the time of the check.
- The initial historical 08:54 failures were not present in the original forwarded source when first searched. They were recovered and ingested separately. The cause of the initial ingestion gap was not established.
- The operational detection uses the `main` index, Ubuntu host, and `/var/log/auth.log` source.
- The search extracts the required fields with `rex` from the raw SSH event.
- The operational search uses a rolling ten-minute window and groups by source IP and target account. It can combine multiple SSH sessions from the same source and account.
- The dashboard uses fixed ten-minute buckets, so its results can differ from the rolling-window scheduled alert.
- The alert runs every five minutes and is therefore scheduled, not instantaneous.
- Password authentication remained enabled in the observed SSH configuration. This is a hardening opportunity, not evidence of compromise.

---

**Stage outcome:** The controlled Linux SSH password-guessing simulation was detected in Splunk, the scheduled alert was triggered and its results were reviewed, the authentication timeline and host state were investigated, and the behavior was mapped to MITRE ATT&CK T1110.001. The four-panel Linux SSH dashboard was created and visually reviewed. Findings are limited to the events and test window recorded above. Genuine screenshots should be added to the referenced evidence paths before publishing.
