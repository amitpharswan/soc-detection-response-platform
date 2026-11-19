Windows VM Setup

Environment

Property| Verified value
Operating System| Windows 11 Home
Version| 10.0.26300
Build| 26300
Architecture| ARM64
Virtualization| QEMU / UTM
RAM| 4 GB
Disk capacity (C:)| 62.95 GB
Available disk space| 42.86 GB
Administrator access| Available

Security Baseline

- Microsoft Defender Antivirus: Enabled
- Real-time protection: Enabled
- Security intelligence version: 1.463.366.0
- Security Event Log: Enabled

Audit Policy

The following audit settings were configured and verified:

Audit category| Configuration
Logon| Success and Failure
Logoff| Success
Special Logon| Success
Other Logon/Logoff Events| Success and Failure
Process Creation| Success

Verification
A controlled Notepad launch was used to test process-creation auditing.

Result: Windows Security Event ID 4688 was successfully recorded.

Three events were observed:

- 19 November 2026, 11:57:00
- 19 November 2026, 11:57:02
- 19 November 2026, 11:57:19

This confirms that Windows process-creation auditing is operational.

Status
Windows VM setup and baseline verification completed.

Detailed Windows telemetry collection, Sysmon, and Splunk forwarding will be configured in their respective project phases.