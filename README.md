Mini-SIEM for Windows

A lightweight Security Information and Event Management (SIEM) tool that monitors Windows Security and Sysmon logs for suspicious activity in real-time.

<img width="472" height="191" alt="Capture d&#39;écran 2026-10-13 110846" src="https://github.com/user-attachments/assets/84dbb5c4-580b-474f-9c2c-43533c97e5f7" />

What It Does

The Mini-SIEM runs every 5 minutes and checks for:

- **Brute Force Attacks** – Detects 5+ failed logins (Event ID 4625) in 5 minutes
- **Suspicious PowerShell** – Detects `Invoke-WebRequest`, `IEX`, `DownloadString`, or `EncodedCommand` usage
- **Suspicious CMD Commands** – Detects reconnaissance commands like `whoami`, `net user`, `ipconfig`
- **Unusual Network Connections** – Detects connections on non-standard ports

When a threat is detected, it:
1. Pops up a Windows alert
2. Logs the event to `SOC_Alerts.txt`
3. Records execution in `SOC_Debug.log`

Requirements

- Windows 10/11
- PowerShell 5.1 or later
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed and running
- Administrator privileges

Installation

1. Clone this repository to your Desktop
2. Open PowerShell as Administrator
3. Run:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\MiniSIEM.ps1

Features

- Severity-based alerting: Alerts classified as LOW, MEDIUM, HIGH, or CRITICAL
- Smart thresholds: 10+ failed logins = CRITICAL, 5-9 = HIGH
- Real-time pop-ups: Icon and title change based on severity
- LAN filtering: Ignores local network traffic (192.168.x, 10.x)
- Automated: Runs every 5 minutes via Task Scheduler
