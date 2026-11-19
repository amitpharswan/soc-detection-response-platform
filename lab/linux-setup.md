# Linux VM Setup

## Environment

| Item | Verified value |
|---|---|
| OS | Ubuntu 26.04.1 LTS |
| Architecture | ARM64 (aarch64) |
| Kernel | 7.0.0-42-generic |
| Hostname | amit-QEMU-Virtual-Machine |
| CPU | 4 CPUs |
| RAM | 2.6 GiB |
| Root disk | 24 GB |
| Available disk space | 12 GB |
| Lab user | victim |
| Sudo access | Available |
| IPv4 address | 192.168.64.5/24 |

## Logging Services

| Component | Verified status |
|---|---|
| systemd-journald | Active |
| rsyslog | Active |
| SSH service | Active |
| SSH listening | Port 22 |

## Verified Log Sources

| Log source | Observation |
|---|---|
| `/var/log/auth.log` | Exists; contains sudo and PAM session events |
| `/var/log/syslog` | Exists; approximately 2.2 KB during initial inspection |
| systemd journal | Approximately 16 MB during initial inspection |
| SSH journal | SSH service startup and listening events observed |
| sudo journal | Sudo session and command events observed |

## Authentication Logging

The rsyslog configuration contains:

`auth,authpriv.* /var/log/auth.log`

Sudo and PAM session events were observed in `/var/log/auth.log`.

Sudo activity was also visible through `journalctl`.

SSH service startup was verified. A fresh SSH authentication event has not yet been tested.

## Scope

This VM is the monitored Linux endpoint for the lab.

Planned telemetry includes:
- Authentication activity
- SSH activity
- System events
- Sudo and privilege-related activity

Log forwarding and Splunk ingestion will be configured in their designated later phases.

## Phase Status

- [x] Linux environment inspected
- [x] SSH service verified
- [x] systemd-journald verified
- [x] rsyslog verified
- [x] Authentication logging rule inspected
- [x] Sudo/PAM events observed
- [ ] Documentation committed to GitHub