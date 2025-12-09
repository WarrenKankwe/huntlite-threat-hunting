## Scenario 1 – Encoded PowerShell Commands

In this scenario, I simulate attacker behavior using harmless but obfuscated PowerShell commands. On a Windows 10 virtual machine, I execute both normal PowerShell activity (Get-Process, Get-Service, directory listings) and PowerShell instances launched with the `-EncodedCommand` flag, which is commonly used to hide script contents from defenders.

Using Event Viewer, I collect Security (Event ID 4688 – new process) and PowerShell Operational logs (Event ID 4104 – script block logging) to build a small, realistic dataset representing suspicious command-line behavior. I then apply the HUNT-LITE framework to form a hypothesis (possible script obfuscation), narrow down indicators (powershell.exe with -EncodedCommand), and triangulate evidence across process creation logs and script block content.

Finally, I create a reusable Sigma rule that detects any use of powershell.exe with `-EncodedCommand` or `-enc`, providing a starting point for SOC teams and students to hunt for encoded PowerShell activity in their own environments.

