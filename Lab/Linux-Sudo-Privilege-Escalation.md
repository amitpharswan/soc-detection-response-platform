# Linux Sudo Privilege Escalation Detection and Investigation

## 1. Overview

This lab demonstrates how an overly broad sudo permission can allow a standard Linux user to execute a nested command with root privileges. The activity was detected in Splunk, investigated, and remediated.

| Metadata | Details |
|---|---|
| Scenario | Controlled sudoers misconfiguration and privileged command execution |
| Date | 22 November 2026 |
| Target | Ubuntu — `amit-QEMU-Virtual-Machine` (`192.168.64.5`) |
| Test account | `labuser` |
| Administrative account | `victim` |
| Splunk index / sourcetype | `main` / `auth-2` |
| Log source | `/var/log/auth.log` |
| Outcome | Unsafe permission detected, investigated, removed, and verified as blocked |

This was an authorized lab exercise, not evidence of an external compromise.

## 2. Attack Simulation

### 2.1 Scenario and baseline

A dedicated account named `labuser` was used to test a sudoers misconfiguration. The existing administrative account `victim` remained available for recovery.

The dedicated file `/etc/sudoers.d/labuser` was created with owner `root:root` and mode `440`.

The initial rule allowed only the following command to run as root:

```text
labuser ALL=(root) /usr/bin/systemctl status ssh
```

The baseline was checked with:

```bash
sudo -l -U labuser
```

The permitted SSH status command worked, while `sudo whoami` was denied.

### 2.2 Deliberately unsafe rule

For the controlled test, this additional rule was added:

```text
labuser ALL=(root) /usr/bin/find
```

The resulting file contained:

```text
labuser ALL=(root) /usr/bin/systemctl status ssh
labuser ALL=(root) /usr/bin/find
```

The sudoers configuration was checked:

```bash
sudo visudo -c
```

Observed output:

```text
/etc/sudoers: parsed OK
```

### 2.3 Controlled test

From the `labuser` session, the following command was executed:

```bash
sudo /usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id \;
```

Observed output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

This confirms that the nested `id` process executed with root identity. It does not demonstrate that an interactive root shell was opened.

### 2.4 Recorded evidence

Ubuntu recorded the command at 10:47:34.883 on 22 November 2026:

```text
2026-11-22T10:47:34.883283+05:30 amit-QEMU-Virtual-Machine sudo: labuser : TTY=/dev/pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id ;
```

Further executions were recorded at 10:59:46.045 and 11:54:54.061. The earlier permitted `systemctl status ssh` command was recorded at 10:37:41.169.

These were repeated executions during the authorized lab exercise, not evidence of separate external intrusions.

## 3. Detection Engineering in Splunk

### 3.1 Confirm that the event is indexed

```spl
index=main
host="amit-QEMU-Virtual-Machine"
source="/var/log/auth.log"
"COMMAND=/usr/bin/find"
| table _time host source sourcetype _raw
| sort -_time
```

The event was verified in index `main`, with host `amit-QEMU-Virtual-Machine`, source `/var/log/auth.log`, and sourcetype `auth-2`.

### 3.2 Extract sudo fields

```spl
index=main
host="amit-QEMU-Virtual-Machine"
source="/var/log/auth.log"
"sudo: labuser"
"USER=root"
"COMMAND=/usr/bin/find"
| rex field=_raw "sudo: (?<executing_user>\w+) : TTY=(?<tty>[^;]+) ; PWD=(?<working_directory>[^;]+) ; USER=(?<run_as_user>\w+) ; COMMAND=(?<executed_command>.*)"
| table _time executing_user run_as_user executed_command working_directory tty
| sort -_time
```

| Field | Meaning |
|---|---|
| `executing_user` | Account that invoked sudo |
| `run_as_user` | Identity requested through sudo |
| `executed_command` | Command recorded by sudo |
| `working_directory` | Current directory when sudo was invoked |
| `tty` | Terminal associated with the command |

The verified event showed `labuser` invoking the command as `root`, from `/home/labuser`, using `/dev/pts/0`.

### 3.3 Compare normal and suspicious activity

```spl
index=main
host="amit-QEMU-Virtual-Machine"
source="/var/log/auth.log"
"sudo: labuser"
"USER=root"
| rex field=_raw "sudo: (?<executing_user>\w+) : TTY=(?<tty>[^;]+) ; PWD=(?<working_directory>[^;]+) ; USER=(?<run_as_user>\w+) ; COMMAND=(?<executed_command>.*)"
| eval activity=if(match(executed_command,"^/usr/bin/find(\s|$)"),"Suspicious - Find execution","Other privileged activity")
| stats count by executing_user run_as_user activity executed_command
```

The observed results distinguished the permitted `/usr/bin/systemctl status ssh` command from the `find` command used in the test. Counts depend on the selected search time range and indexed events.

### 3.4 Targeted detection search

```spl
index=main
host="amit-QEMU-Virtual-Machine"
source="/var/log/auth.log"
"sudo: labuser"
"USER=root"
"COMMAND=/usr/bin/find"
| rex field=_raw "sudo: (?<executing_user>\w+) : TTY=(?<tty>[^;]+) ; PWD=(?<working_directory>[^;]+) ; USER=(?<run_as_user>\w+) ; COMMAND=(?<executed_command>.*)"
| eval detection_name="Potential Sudo Privilege Escalation via Find"
| eval severity="High"
| table _time detection_name severity executing_user run_as_user executed_command working_directory tty
| sort -_time
```

The search narrows events to `labuser`, root as the target identity, and the `/usr/bin/find` command. `rex` extracts context, `eval` adds a detection name and lab severity, and `table` displays the fields needed for triage.

The High value is the configured lab detection severity, not an automatic production incident rating.

### 3.5 Scheduled alert configuration

| Setting | Configured value |
|---|---|
| Alert name | `Linux - Potential Sudo Privilege Escalation via Find` |
| Type | Scheduled |
| Schedule | Every five minutes (`*/5 * * * *`) |
| Time range in alert editor | Last 15 minutes |
| SPL lookback | `earliest=-10m` |
| Trigger condition | Number of results greater than 0 |
| Trigger setting | Once |
| Throttle | 10 minutes |
| Action | Add to Triggered Alerts |
| Permissions | Private |
| Severity | High |
| Expiration | 24 hours |
| External notifications | None configured |

The alert was saved and enabled. A High-severity alert was generated after a fresh test. Earlier scheduled searches returned zero events when the previous test event had fallen outside the configured time range; a fresh event was generated for validation.

### Detection limitation

This search is deliberately specific to `labuser` and `/usr/bin/find`. It is useful for this lab scenario, but it is not a general detector for every sudo abuse technique or sudoers misconfiguration. Production use would require broader command and user context, approved-activity baselines, and monitoring of sudoers file changes.

### 3.6 Dashboard

The private Dashboard Studio dashboard was saved, and all four panels were confirmed as displaying correctly.

**Dashboard:** `Linux Sudo Privilege Escalation Monitoring`

| Panel | Visualization | Purpose |
|---|---|---|
| Privileged Activity Over Time | Line chart | Root-targeted sudo activity over time |
| Users Executing Commands as Root | Bar chart | Privileged commands grouped by invoking user |
| Suspicious Find Execution | Compact table | Detection, severity, and detection count |
| Privileged Activity Summary | Compact table | User, activity classification, and command count |

The summary panels intentionally omit long command strings and terminal details. Those remain available in Splunk Search for deeper investigation.

**Screenshot evidence to add:** Add genuine screenshots when available. Suggested paths:

- `evidence/linux/linux-sudo-dashboard.png`
- `evidence/linux/linux-sudo-detection.png`

No screenshots were supplied with the source document. Add the actual screenshots before publishing.

## 4. MITRE ATT&CK Mapping

| Field | Mapping |
|---|---|
| Tactic | Privilege Escalation |
| Technique | [T1548.003 — Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |

**Justification:** The test demonstrated abuse of a sudo permission to execute a nested command as root. This is relevant to sudo abuse. The mapping describes the technique exercised in the lab; it does not imply that an external attacker compromised the host.

## 5. SOC Investigation and Triage

### 5.1 Findings

The broad search for `labuser` sudo activity returned four records:

| Time (22 November 2026, IST) | User | Run as | Command |
|---|---|---|---|
| 10:37:41.169 | `labuser` | `root` | `/usr/bin/systemctl status ssh` |
| 10:47:34.883 | `labuser` | `root` | `/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id ;` |
| 10:59:46.045 | `labuser` | `root` | `/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id ;` |
| 11:54:54.061 | `labuser` | `root` | `/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id ;` |

The first record matched the intended restricted command. The remaining three matched the deliberately unsafe permission.

### 5.2 Review of the surrounding authentication log

A search for `labuser` between 11:45 and 12:10 returned one event: the 11:54:54.061 sudo `find` execution.

A search for successful SSH authentication (`Accepted`) in the same window returned no results.

These checks establish only what was returned by the specified searches against indexed `/var/log/auth.log` data. They do not prove that no other host activity occurred.

### 5.3 Root execution and analyst assessment

The `uid=0(root)` output confirms that the nested `id` process ran as root. The sudo event records the invoking account, target identity, and command. Neither source demonstrates an interactive root shell or additional system changes.

The unsafe sudoers entry created a real privilege-escalation path in the controlled lab. The demonstrated capability had high potential impact because a non-administrative account could execute a command as root. This is an assessment of the misconfiguration and demonstrated capability, not a claim of an external compromise.

**Screenshot evidence to add:** Include genuine screenshots of the Splunk investigation results and alert if captured. Suggested paths:

- `evidence/linux/linux-sudo-investigation.png`
- `evidence/linux/linux-sudo-alert.png`

Do not create substitute screenshots.

## 6. Containment and Remediation

### 6.1 Immediate remediation

The unsafe rule was removed from `/etc/sudoers.d/labuser` using `visudo`. The original restricted rule was retained:

```text
labuser ALL=(root) /usr/bin/systemctl status ssh
```

The following checks were completed.

**Sudoers syntax**

```bash
sudo visudo -c
```

Observed output:

```text
/etc/sudoers: parsed OK
```

**Permission listing**

`sudo -l -U labuser` no longer listed `/usr/bin/find`. The original SSH status permission remained.

**Blocked test**

```bash
sudo /usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id \;
```

Observed output after remediation:

```text
sudo: I'm sorry labuser. I'm afraid I can't do that
```

**File ownership and mode**

```bash
sudo stat -c '%a %U:%G %n' /etc/sudoers.d/labuser
```

Observed output:

```text
440 root:root /etc/sudoers.d/labuser
```

**Legitimate command**

`sudo /usr/bin/systemctl status ssh` continued to work for `labuser`.

### 6.2 Remediation outcome

The demonstrated `find`-based privilege-escalation path was blocked, and the original restricted SSH status command remained available. The sudoers file retained `root:root` ownership and mode `440`.

The `labuser` account was retained for the lab. No unrelated hardening changes or account deletion are claimed.

### 6.3 Hardening recommendations

- Grant only the exact administrative commands a user needs.
- Avoid granting sudo access to general-purpose utilities or interpreters with command-execution features unless the risk is understood.
- Edit sudoers files with `visudo` and validate changes.
- Monitor changes to `/etc/sudoers` and `/etc/sudoers.d/` with an appropriate audit or file-integrity mechanism.
- Review privileged commands in context; a command executed as root is not automatically malicious.
- Keep test accounts separate from administrative recovery accounts.

## 7. Lessons Learned and Visibility Gaps

- A seemingly narrow sudo rule can be unsafe when the allowed program supports execution of other commands.
- Ubuntu sudo records provide useful fields: invoking user, target identity, terminal, working directory, and command.
- The detection works for the tested `labuser` and `find` command pattern; it will not identify every possible sudo abuse path.
- The investigation was limited to indexed `/var/log/auth.log` events and the selected time window. Process auditing and file-integrity telemetry would provide additional visibility.
- The root identity output proves the nested `id` process ran as root. It does not prove an interactive root shell or further system changes.

**Screenshot evidence to add:** Include genuine screenshots of the initial sudoers rule, unsafe rule, root execution output, Splunk detection, triggered alert, dashboard, denied command, and preserved permitted command if captured.

---

**Stage outcome:** The controlled sudoers misconfiguration was introduced, exercised, detected in Splunk, investigated, and remediated. The unsafe permission was removed and the original restricted command was verified as working. The four-panel dashboard was saved and confirmed. Findings are limited to the lab events and checks recorded above.
