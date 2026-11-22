# Stage 4 --- Windows Local Account Creation and Administrators Group Modification

## Overview

**Scenario:** Detect and investigate creation of an unexpected local
Windows account followed by its addition to the local Administrators
group.

**Host:** `DESKTOP-PPSKJ22`\
**Splunk index:** `main`\
**Sourcetype:** `XmlWinEventLog:Security`\
**Source:** `WinEventLog:Security`\
**Authorized lab administrator:** `window`

This was an authorized lab simulation, not evidence of a real
compromise.

## Objectives

-   Detect local account creation.
-   Detect additions to the local Administrators group.
-   Identify the initiating account and affected account.
-   Investigate related authentication activity.
-   Validate the Splunk search and scheduled alert.
-   Remove temporary test accounts.

## Relevant Windows events

  -----------------------------------------------------------------------
  Event ID                Meaning                 Use
  ----------------------- ----------------------- -----------------------
  4720                    A user account was      Account creation
                          created                 detection

  4732                    A member was added to a Local group membership
                          security-enabled local  detection
                          group                   

  4624                    Successful logon        Account-use
                                                  investigation

  4625                    Failed logon            Failed-authentication
                                                  investigation
  -----------------------------------------------------------------------

Local Administrators group SID: `S-1-5-32-544`.

## Baseline

A dedicated standard account `labuser` was created and verified as not
belonging to Administrators. A PowerShell session launched as `labuser`
showed `desktop-ppskj22\labuser`; `whoami /groups` did not show
Administrators. `net session` returned Access Denied. This established
the standard-user baseline.

## Initial test and forwarding gap

The authorized administrator `window` created `backup_admin` and added
it to Administrators.

-   Event 4720: 22 November 2026, approximately 12:51:18; actor
    `window`; account `backup_admin`; SID suffix `-1004`.
-   Event 4732: 22 November 2026, approximately 12:52:02; actor
    `window`; group `Administrators`; member SID suffix `-1004`; target
    group SID `S-1-5-32-544`.

Both events were verified locally in Windows Security logs but were not
found in Splunk.

The Windows Universal Forwarder receiver was corrected to
`10.244.150.12:9997`. The service was restarted, TCP connectivity was
tested, and Event Log Readers permissions were reviewed.
`NT SERVICE\SplunkForwarder` was added to Event Log Readers. New Windows
Security events then began arriving in Splunk. The original
`backup_admin` events were not recovered; no checkpoint reset or
historical backfill was performed. The exact reason those original
records were not forwarded was not established.

## Fresh test and successful ingestion

After forwarding was corrected, a fresh account `soc_tempadmin` was
created and added to Administrators.

**Event 4720** - Time: 22 November 2026, 13:31:48.778 - Actor:
`window` - Created account: `soc_tempadmin` - SID suffix: `-1005`

**Event 4732** - Time: 22 November 2026, 13:33:21.546 - Actor:
`window` - Group: `Administrators` - Member SID: same SID ending
`-1005` - Target group SID: `S-1-5-32-544`

Both events were confirmed in Splunk under `index=main`, host
`DESKTOP-PPSKJ22`, sourcetype `XmlWinEventLog:Security`.

## Detection search

``` spl
index=main host="DESKTOP-PPSKJ22" earliest=-10m
| rex field=_raw "<EventID>(?<event_id>\d+)</EventID>"
| search event_id=4720 OR event_id=4732
| rex field=_raw "<Data Name='SubjectUserName'>(?<actor>[^<]*)</Data>"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]*)</Data>"
| rex field=_raw "<Data Name='MemberSid'>(?<member_sid>[^<]*)</Data>"
| rex field=_raw "<Data Name='TargetSid'>(?<target_sid>[^<]*)</Data>"
| eval activity=case(
    event_id="4720","Local account created",
    event_id="4732" AND target_sid="S-1-5-32-544","Member added to Administrators"
)
| where event_id="4720" OR (event_id="4732" AND target_sid="S-1-5-32-544")
| stats count values(activity) as activities values(actor) as actors values(target_user) as target_users values(member_sid) as member_sids by host
```

The validated search returned two relevant activities: account creation
and addition to Administrators. The actor was `window`.

## Scheduled alert

**Name:**
`Windows - Unauthorized Account Creation and Admin Group Addition`

  Setting             Value
  ------------------- -----------------------------
  Schedule            Every 5 minutes
  Search lookback     Last 10 minutes
  Trigger condition   Result count greater than 0
  Trigger mode        Once
  Severity            High
  Throttle            10 minutes
  Expiration          24 hours
  Action              Triggered Alerts

The user confirmed the alert was saved. High is the configured detection
severity, not a conclusion that the authorized lab activity was a
compromise.

## Investigation

For `soc_tempadmin`, Event IDs 4624 and 4625 were searched over the last
24 hours. No matching events were found in that searched window. The
account was enabled and its `LastLogon` property was blank at
inspection. The local Administrators group was reviewed.

These findings do not prove the account was never used; they describe
only the evidence and time window examined.

## MITRE ATT&CK mapping

  -----------------------------------------------------------------------
  Technique               Name                    Evidence
  ----------------------- ----------------------- -----------------------
  T1136.001               Create Account: Local   Event 4720
                          Account                 

  T1098.007               Account Manipulation:   Event 4732
                          Additional Local or     
                          Domain Groups           
  -----------------------------------------------------------------------

These mappings describe the simulated actions and do not attribute them
to a real adversary.

## Severity

-   **Configured alert severity:** High.
-   **Actual lab assessment:** Authorized Security Test --- No confirmed
    compromise.

An unexpected account added to local Administrators in a real
environment warrants high-priority investigation because it can provide
privileged access and support persistence.

## Response and cleanup

`soc_tempadmin` was removed from Administrators and deleted. Its absence
from the account list and Administrators group was verified.

`backup_admin` was also removed. The final verified Administrators group
listing contained `DESKTOP-PPSKJ22\Administrator` and
`DESKTOP-PPSKJ22\window`.

## Dashboard

**Name:** `Windows Account Manipulation Monitoring`\
**Type:** Splunk Dashboard Studio

The user confirmed these four panels: 1. Local Account Creation Events
2. Administrators Group Membership Changes 3. Recent Account Management
Activity 4. Account Management Activity by Actor

Dashboard creation was confirmed by the operator. No genuine dashboard
screenshots have been supplied.

## Limitations

-   Original `backup_admin` events were not recovered in Splunk.
-   Successful ingestion and detection validation used the fresh
    `soc_tempadmin` test.
-   No process-creation evidence was collected to identify the exact
    executable or command.
-   No matching 4624/4625 events were found in the searched 24-hour
    window; this does not prove the account was never used.
-   The privileged actions were performed by authorized administrator
    `window`; the test did not demonstrate an unprivileged user
    independently bypassing Windows access controls.
-   The exact reason the original events were not forwarded was not
    confirmed.

## Final assessment

Fresh Windows account-management events were received by Splunk, the
detection search returned the expected results, the scheduled alert was
saved, the Dashboard Studio dashboard was created, and temporary account
cleanup was verified.

**Outcome:** Authorized Security Test --- Detection Validated ---
Cleanup Verified. **Evidence note:** Dashboard creation was confirmed by
the operator; genuine screenshots are not attached.
