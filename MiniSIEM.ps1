# Mini-SIEM for Windows (Final Version)

$Desktop   = [Environment]::GetFolderPath("Desktop")
$AlertFile = Join-Path $Desktop "SOC_Alerts.txt"
$LogFile   = Join-Path $Desktop "SOC_Debug.log"

function Write-Alert {
    param($Message)
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $AlertFile -Value "[$Time] $Message"
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Message, "SOC ALERT", 0, 48) | Out-Null
}

function Write-DebugLog {
    param($Message)
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$Time] $Message"
}

Write-DebugLog "Mini-SIEM check started."

# --- 1. Brute Force Detection (Event ID 4625) ---
$FailedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue
if ($FailedLogins) {
    $Recent = $FailedLogins | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }
    if ($Recent.Count -ge 5) {
        Write-Alert "BRUTE FORCE DETECTED: $($Recent.Count) failed logins in the last 5 minutes."
    }
}

# --- 2. Suspicious Process Creation (Sysmon Event ID 1) ---
$ProcEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 -ErrorAction SilentlyContinue
foreach ($Event in $ProcEvents) {
    [xml]$xml = $Event.ToXml()
    $Image       = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
    $CommandLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
    
    # Ignore our own script
    if ($CommandLine -match "MiniSIEM.ps1") { continue }

    if ($Image -match "powershell.exe" -and $CommandLine -match "Invoke-WebRequest|IEX|DownloadString|EncodedCommand|bypass") {
        Write-Alert "SUSPICIOUS POWERSHELL: $CommandLine"
    }
    if ($Image -match "cmd.exe" -and $CommandLine -match "net user|whoami|ipconfig|net localgroup") {
        Write-Alert "SUSPICIOUS CMD: $CommandLine"
    }
}

# --- 3. Unusual Network Connections (Sysmon Event ID 3) ---
$NetEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} -MaxEvents 100 -ErrorAction SilentlyContinue
foreach ($Event in $NetEvents) {
    [xml]$xml = $Event.ToXml()
    $DestIP   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text'
    $DestPort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationPort' }).'#text'
    
    # Ignore local multicast traffic (mDNS, SSDP, etc.)
    if ($DestIP -match "^ff02:" -or $DestIP -match "^224\.0\.0") { continue }
    
    # Ignore benign common ports
    if ($DestPort -and $DestPort -notin @(80,443,53,22,3389,8080,5353,1900)) {
        Write-Alert "UNUSUAL PORT CONNECTION: $DestIP on port $DestPort"
    }
}

Write-DebugLog "Mini-SIEM check completed."
    }
}
Write-DebugLog "Mini-SIEM check completed."
