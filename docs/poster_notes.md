## Scenario 1 – Encoded PowerShell Commands

In this scenario, I simulate attacker behavior using harmless but obfuscated PowerShell commands. On a Windows 10 virtual machine, I execute both normal PowerShell activity (Get-Process, Get-Service, directory listings) and PowerShell instances launched with the `-EncodedCommand` flag, which is commonly used to hide script contents from defenders.

Using Event Viewer, I collect Security (Event ID 4688 – new process) and PowerShell Operational logs (Event ID 4104 – script block logging) to build a small, realistic dataset representing suspicious command-line behavior. I then apply the HUNT-LITE framework to form a hypothesis (possible script obfuscation), narrow down indicators (powershell.exe with -EncodedCommand), and triangulate evidence across process creation logs and script block content.

Finally, I create a reusable Sigma rule that detects any use of powershell.exe with `-EncodedCommand` or `-enc`, providing a starting point for SOC teams and students to hunt for encoded PowerShell activity in their own environments.


## Scenario 2 – Failed Authentication (Brute-force Simulation)

To simulate a realistic authentication attack, I generated repeated failed logon attempts (Event ID 4625) inside a Windows 10 VM. Using the `runas` command with an intentionally incorrect password, I produced a cluster of authentication failures during a short window, which mirrors attacker brute-force behavior.

In Event Viewer (Security logs), I filtered for Event ID 4625 and observed multiple consecutive failures with the same account, consistent with password-guessing attempts. I then exported the filtered logs to create a reproducible dataset for analysis.

Using HUNT-LITE, I formed the hypothesis that repeated authentication failures within a tight timeframe may represent brute-force activity. I validated this pattern by correlating timestamps and identifying a clear burst of related events.

I implemented a Sigma rule that triggers when 5 or more failed logon attempts occur within 2 minutes. This provides a simple, portable detection method for credential-based attacks and aligns with MITRE ATT&CK technique T1110 (Brute Force).


## Scenario 3 – Network Beaconing (PCAP Analysis)

In this scenario, I analyzed a packet capture that exhibited strong signs of automated command-and-control (C2) beaconing. Using Wireshark, I focused on DNS activity, HTTP request patterns, and packet timing to identify recurring communication between an internal host and a suspicious external server.

The internal workstation 10.1.17.215 generated a high volume of DNS queries, including long and unusual domain strings that repeated multiple times. This type of DNS noise is commonly associated with malware resolving its controller domains or fallback infrastructure.

The HTTP traffic showed the clearest indicator of beaconing. The host repeatedly sent hundreds of identical GET requests to the external IP 5.252.153.241, specifically requesting the same resource:

`GET /1517096937 HTTP/1.1`

This single repeated URI path — coupled with frequent 404 Not Found responses — is characteristic of C2 check-in behavior, where malware polls a server for instructions at regular intervals. Legitimate applications rarely send an identical request hundreds of times without user interaction.

To validate the hypothesis of beaconing, I reviewed network timing. Using Wireshark’s IO Graphs and the “Delta time displayed” column, I observed that packets to 5.252.153.241 occurred in consistent, predictable intervals, forming a periodic “heartbeat” pattern. Even with normal workstation noise mixed in, the repeated timing stood out clearly in both 1-second and 5-second interval graphs.

Applying the HUNT-LITE framework, I correlated three independent signals—repetitive DNS activity, a dominant repeated HTTP request, and regular timing intervals—to confirm likely beaconing behavior. This scenario demonstrates how early detection can occur before payload execution or lateral movement, making beaconing one of the most important network hunting patterns for SOC analysts.
