## Scenario 1 – Encoded PowerShell Commands

In this scenario, I simulate attacker behavior using harmless but obfuscated PowerShell commands. On a Windows 10 virtual machine, I execute both normal PowerShell activity (Get-Process, Get-Service, directory listings) and PowerShell instances launched with the `-EncodedCommand` flag, which is commonly used to hide script contents from defenders.

Using Event Viewer, I collect Security (Event ID 4688 – new process) and PowerShell Operational logs (Event ID 4104 – script block logging) to build a small, realistic dataset representing suspicious command-line behavior. I then apply the HUNT-LITE framework to form a hypothesis (possible script obfuscation), narrow down indicators (powershell.exe with -EncodedCommand), and triangulate evidence across process creation logs and script block content.

Finally, I create a reusable Sigma rule that detects any use of powershell.exe with `-EncodedCommand` or `-enc`, providing a starting point for SOC teams and students to hunt for encoded PowerShell activity in their own environments.


## Scenario 2 – Failed Authentication (Brute-force Simulation)

To simulate a realistic authentication attack, I generated repeated failed logon attempts (Event ID 4625) inside a Windows 10 VM. Using the `runas` command with an intentionally incorrect password, I produced a cluster of authentication failures during a short window, which mirrors attacker brute-force behavior.

In Event Viewer (Security logs), I filtered for Event ID 4625 and observed multiple consecutive failures with the same account, consistent with password-guessing attempts. I then exported the filtered logs to create a reproducible dataset for analysis.

Using HUNT-LITE, I formed the hypothesis that repeated authentication failures within a tight timeframe may represent brute-force activity. I validated this pattern by correlating timestamps and identifying a clear burst of related events.

I implemented a Sigma rule that triggers when 5 or more failed logon attempts occur within 2 minutes. This provides a simple, portable detection method for credential-based attacks and aligns with MITRE ATT&CK technique T1110 (Brute Force).

