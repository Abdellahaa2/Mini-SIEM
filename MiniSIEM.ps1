# Mini-SIEM for Windows (v2.0 - With Severity Levels)

$Desktop   = [Environment]::GetFolderPath("Desktop")
$AlertFile = Join-Path $Desktop "SOC_Alerts.txt"
$LogFile   = Join-Path $Desktop "SOC_Debug.log"

function Write-Alert {
    param(
        [string]$Message,
        [string]$Severity = "LOW"
    )
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Time] [$Severity] $Message"
    Add-Content -Path $AlertFile -Value $Entry
    
    $Icon = switch ($Severity) {
        "CRITICAL" { 16 }
        "HIGH"     { 48 }
        "MEDIUM"   { 48 }
        default    { 64 }
    }
    
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($Message, "SOC ALERT [$Severity]", 0, $Icon) | Out-Null
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
    if ($Recent.Count -ge 10) {
        Write-Alert "BRUTE FORCE: $($Recent.Count) failed logins in last 5 min." -Severity "CRITICAL"
    } elseif ($Recent.Count -ge 5) {
        Write-Alert "Possible brute force: $($Recent.Count) failed logins in last 5 min." -Severity "HIGH"
    }
}

# --- 2. Suspicious Process Creation (Sysmon Event ID 1) ---
$ProcEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 -ErrorAction SilentlyContinue
foreach ($Event in $ProcEvents) {
    [xml]$xml = $Event.ToXml()
    $Image       = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
    $CommandLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
    
    if ($CommandLine -match "MiniSIEM.ps1") { continue }

    if ($Image -match "powershell.exe" -and $CommandLine -match "EncodedCommand|DownloadString|IEX") {
        Write-Alert "SUSPICIOUS POWERSHELL (Encoded/Download): $CommandLine" -Severity "CRITICAL"
    } elseif ($Image -match "powershell.exe" -and $CommandLine -match "Invoke-WebRequest|bypass") {
        Write-Alert "Suspicious PowerShell activity: $CommandLine" -Severity "HIGH"
    }
    
    if ($Image -match "cmd.exe" -and $CommandLine -match "net user|net localgroup") {
        Write-Alert "Suspicious CMD (user enumeration): $CommandLine" -Severity "HIGH"
    } elseif ($Image -match "cmd.exe" -and $CommandLine -match "whoami|ipconfig") {
        Write-Alert "CMD recon activity: $CommandLine" -Severity "MEDIUM"
    }
}

# --- 3. Unusual Network Connections (Sysmon Event ID 3) ---
$NetEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} -MaxEvents 100 -ErrorAction SilentlyContinue
foreach ($Event in $NetEvents) {
    [xml]$xml = $Event.ToXml()
    $DestIP   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationIp' }).'#text'
    $DestPort = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'DestinationPort' }).'#text'
    
    if ($DestIP -match "^ff02:" -or $DestIP -match "^224\.0\.0") { continue }
    if ($DestIP -match "^192\.168\." -or $DestIP -match "^10\.") { continue }
    
    if ($DestPort -and $DestPort -notin @(80,443,53,22,3389,8080,5353,1900)) {
        Write-Alert "Unusual port connection: $DestIP on port $DestPort" -Severity "MEDIUM"
    }
}

Write-DebugLog "Mini-SIEM check completed."
