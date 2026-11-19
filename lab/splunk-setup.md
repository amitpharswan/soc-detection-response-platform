Splunk Environment Setup and Verification

1. Splunk Environment

Property| Verified value
Platform| macOS on Apple Silicon
Splunk server name| "amits-MacBook-Air.local"
Splunk version| "10.6.1.1"
Build| "b2ae2962645c"
Splunk user| "Amit"
Role| "Admin"
Splunk Web| "http://localhost:8000"

2. Existing Index Inspection

The following indexes were visible during the initial inspection:

"_audit", "_configtracker", "_dsappevent", "_dsclient", "_dsphonehome", "_internal", "_introspection", "_telemetry", "_thefishbucket", "history", "main", "splunklogger", "summary".

Observed data:

- "_internal" contained 304,703 events at the time of inspection.
- "main" reported zero events.
- "history" and "summary" reported zero events.
- Internal Splunk sourcetypes included "splunkd", "splunkd_ui_access", "splunkd_access", "splunk_web_service", and other Splunk operational sources.

No Windows or Linux endpoint event ingestion was established during this phase.

3. Existing Data Inputs

The REST inspection returned 70 configured inputs, of which 34 were enabled.

The inspected enabled inputs were primarily associated with Splunk's built-in monitoring, instrumentation, and application components.

Existing inputs were inspected without modifying their configuration.

4. Splunk Receiving Port

An enabled TCP cooked input was found with these reported properties:

Property| Value
Port| "9997"
Disabled| "0"
Index setting| "default"
Connection host setting| "ip"

The REST endpoint "/services/data/inputs/tcp/server" returned HTTP 404 during inspection. This endpoint was not used as evidence of receiver status.

The Mac host was independently checked using:

lsof -nP -iTCP:9997 -sTCP:LISTEN

Verified result:

- Process: "splunkd"
- PID: "12655"
- Listening address: "*:9997"

5. VM-to-Splunk Network Connectivity

The Mac's UTM virtual-network address is "192.168.64.1".

Connectivity to TCP port 9997 was tested from all three virtual machines:

Source VM| Destination| Result
Ubuntu| "192.168.64.1:9997"| Successful
Kali| "192.168.64.1:9997"| Successful
Windows| "192.168.64.1:9997"| "TcpTestSucceeded: True"

These tests verify network reachability to the Splunk receiving port. They do not establish that a forwarder is connected or that endpoint events are being ingested.

6. Verification Boundary

Completed in this phase:

- Splunk Web access and administrative role verified.
- Splunk version and build verified.
- Existing indexes and internal event data inspected.
- Existing data inputs inspected.
- TCP 9997 listener verified on the Mac.
- TCP connectivity from Ubuntu, Kali, and Windows verified.

Not yet established:

- Windows Security event ingestion.
- Sysmon event ingestion.
- Linux endpoint event ingestion.
- Successful forwarding and indexing of endpoint telemetry.

These items will be verified in their designated later phases.

7. Configuration Safety

No existing indexes, inputs, receiving ports, or Splunk configurations were changed during this verification phase.