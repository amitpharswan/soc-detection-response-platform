Lab Networking

1. Network Overview

The lab uses a shared virtual network for communication between the Mac host and the three virtual machines.

Lab subnet: "192.168.64.0/24"

Machine| Operating System| Interface| IPv4 Address
Host| macOS| bridge100| 192.168.64.1
Target VM| Ubuntu| enp0s1| 192.168.64.5
Testing VM| Kali Linux| eth0| 192.168.64.6
Endpoint VM| Windows 11| Ethernet| 192.168.64.8

2. Default Gateway

The Ubuntu, Kali, and Windows VMs use "192.168.64.1" as their default gateway.

The Mac's Wi-Fi interface uses a separate network and is not part of the VM subnet.

3. Connectivity Verification

Connectivity was tested using ICMP ping.

Test| Result
Windows to Mac| Successful
Windows to Ubuntu| Successful
Windows to Kali| Successful
Kali to Mac| Successful
Kali to Ubuntu| Successful on retest
Ubuntu to Mac| Successful
Ubuntu to Kali| Successful on retest
Mac to Ubuntu| Successful
Mac to Kali| Successful

The SSH TCP connectivity test from Kali to Ubuntu on port 22 was also successful.

ICMP ping tests to Windows from the Linux VMs and Mac did not receive replies during the initial tests. This behavior was recorded without changing firewall settings.

4. Neighbor Discovery

IPv4 neighbor tables were inspected on Windows, Kali, and Ubuntu.

The tables contained MAC address entries for the other lab machines, confirming that neighbor discovery had occurred.

Some entries were reported as "STALE". This is a neighbor-cache state and does not, by itself, indicate a connectivity failure.

5. Network Safety

- Testing is restricted to the user's own virtual lab.
- No third-party systems are included.
- Firewall settings were not disabled to make ping tests succeed.
- No static IP addresses or routing changes were introduced during verification.

6. Phase Status

Phase 5 — Lab Networking: Completed

The lab network addressing, default gateway information, neighbor discovery, and required VM connectivity tests have been verified.