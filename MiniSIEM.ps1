# Load API key from config file
$ConfigPath = Join-Path $PSScriptRoot "config.ps1"
if (Test-Path $ConfigPath) { . $ConfigPath }

# Mini-SIEM for Windows

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

function Generate-Dashboard {
    param($AlertFilePath, $OutputHtmlPath)
    
    if (-not (Test-Path $AlertFilePath)) { return }
    
    $lines = Get-Content $AlertFilePath -ErrorAction SilentlyContinue
    $critical = ($lines | Select-String "\[CRITICAL\]").Count
    $high     = ($lines | Select-String "\[HIGH\]").Count
    $medium   = ($lines | Select-String "\[MEDIUM\]").Count
    $low      = ($lines | Select-String "\[LOW\]").Count
    $total    = $lines.Count
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="30">
<title>Mini-SIEM Dashboard</title>
<style>
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 30px; }
    h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 15px; margin-top: 0; }
    .subtitle { color: #8b949e; margin-top: -10px; margin-bottom: 30px; font-size: 14px; }
    .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
    .card { padding: 25px 20px; border-radius: 10px; text-align: center; }
    .card h2 { font-size: 48px; margin: 0; }
    .card p { margin: 8px 0 0 0; font-size: 13px; text-transform: uppercase; letter-spacing: 2px; }
    .critical { background: #58151c; color: #ff7b72; border: 1px solid #f85149; }
    .high     { background: #5a1e02; color: #ffa657; border: 1px solid #db6d28; }
    .medium   { background: #4d3800; color: #e3b341; border: 1px solid #d29922; }
    .low      { background: #0d2847; color: #79c0ff; border: 1px solid #388bfd; }
    .total-bar { background: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; color: #8b949e; }
    .total-bar strong { color: #58a6ff; font-size: 20px; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }
    th { background: #21262d; color: #58a6ff; padding: 14px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
    td { padding: 12px 14px; border-top: 1px solid #30363d; font-family: 'Consolas', monospace; font-size: 13px; }
    tr:hover { background: #1c2128; }
    .tag-critical { color: #ff7b72; font-weight: bold; }
    .tag-high     { color: #ffa657; font-weight: bold; }
    .tag-medium   { color: #e3b341; font-weight: bold; }
    .tag-low      { color: #79c0ff; font-weight: bold; }
    .footer { text-align: center; color: #8b949e; margin-top: 30px; font-size: 12px; }
</style>
</head>
<body>
    <h1>🛡️ Mini-SIEM Dashboard</h1>
    <p class="subtitle">Auto-refreshes every 30 seconds &nbsp;|&nbsp; Last updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <div class="cards">
        <div class="card critical"><h2>$critical</h2><p>Critical</p></div>
        <div class="card high"><h2>$high</h2><p>High</p></div>
        <div class="card medium"><h2>$medium</h2><p>Medium</p></div>
        <div class="card low"><h2>$low</h2><p>Low</p></div>
    </div>
    
    <div class="total-bar">Total alerts logged: <strong>$total</strong></div>
    
    <table>
        <thead>
            <tr><th style="width: 180px;">Timestamp</th><th style="width: 100px;">Severity</th><th>Alert Details</th></tr>
        </thead>
        <tbody>
"@

    foreach ($line in $lines) {
        if ($line -match "^\[(.*?)\] \[(.*?)\] (.*)$") {
            $time = $matches[1]
            $sev = $matches[2]
            $msg = $matches[3]
            $cls = "tag-" + $sev.ToLower()
            $html += "<tr><td>$time</td><td class='$cls'>$sev</td><td>$msg</td></tr>`n"
        }
    }

    $html += @"
        </tbody>
    </table>
    <div class="footer">Mini-SIEM v3.0 &nbsp;|&nbsp; Built with PowerShell &nbsp;|&nbsp; $(Get-Date -Format 'yyyy')</div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputHtmlPath -Encoding UTF8
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

# --- VirusTotal IP Lookup ---
$script:VTCache = @{}

function Get-VirusTotalReputation {
    param([string]$IPAddress)
    
    if (-not $VT_API_KEY) { return "VT: no API key" }
    if ($script:VTCache.ContainsKey($IPAddress)) { return $script:VTCache[$IPAddress] }
    
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$IPAddress"
    $headers = @{ "x-apikey" = $VT_API_KEY }
    
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        Start-Sleep -Seconds 16   # Respect free tier: 4 requests/minute
        
        $stats = $response.data.attributes.last_analysis_stats
        $malicious = $stats.malicious
        $suspicious = $stats.suspicious
        $total = $stats.harmless + $stats.malicious + $stats.suspicious + $stats.undetected
        
        $result = "VT: $malicious malicious / $suspicious suspicious / $total engines"
        $script:VTCache[$IPAddress] = $result
        return $result
    }
    catch {
        $script:VTCache[$IPAddress] = "VT: lookup failed"
        return "VT: lookup failed"
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
    
   if ($DestPort -eq "443" -or $DestPort -eq "80" -or $DestPort -eq "53" -or $DestPort -eq "22") { continue }
if ($DestPort -and $DestPort -notin @(3389,8080,5353,1900)) {
        $vtResult = Get-VirusTotalReputation -IPAddress $DestIP
        Write-Alert "Unusual port connection: $DestIP on port $DestPort | $vtResult" -Severity "MEDIUM"
    }
}

Write-DebugLog "Mini-SIEM check completed."

# --- 4. Generate HTML Dashboard ---
$DashboardFile = Join-Path $Desktop "index.html"
Generate-Dashboard -AlertFilePath $AlertFile -OutputHtmlPath $DashboardFile

v4.1 - Strengthen network whitelist to reduce false positives
