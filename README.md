# Mini-SIEM for Windows

A lightweight Security Information and Event Management (SIEM) tool that monitors Windows Security and Sysmon logs for suspicious activity in real-time.

<img width="472" height="191" alt="Capture d&#39;écran 2026-10-13 110846" src="https://github.com/user-attachments/assets/84dbb5c4-580b-474f-9c2c-43533c97e5f7" />

## 🎯 Features

- Live HTML Dashboard – Color-coded, auto-refreshing web dashboard showing all alerts by severity
- Severity-based alerting: Alerts classified as LOW, MEDIUM, HIGH, or CRITICAL
- Smart thresholds: 10+ failed logins = CRITICAL, 5-9 = HIGH
- Real-time pop-ups: Icon and title change based on severity
- Detects: Brute force, suspicious PowerShell, suspicious CMD, unusual ports
- Automated: Runs every 5 minutes via Task Scheduler
- Logging: All alerts written to `SOC_Alerts.txt`

## 📸 Dashboard Preview


<img width="1887" height="907" alt="Capture d&#39;écran 2026-10-13 143619" src="https://github.com/user-attachments/assets/63696295-7291-4ea6-bf72-34def5815e5d" />
