# ==========================
# ProcessAnalyzer (GL1T0H)
# ==========================

param(
    [int]$ProcessId,
    [string]$ProcessName,
    [switch]$ExportHtml
)

$TelegramBotToken = "YOUR_TELEGRAM_BOT_TOKEN"
$TelegramChatID = "YOUR_CHAT_ID"
$AbuseIPDBApiKey = "YOUR_ABUSEIPDB_API_KEY"
$VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY"


function Show-Help {
    Write-Output @"
Usage: .\script.ps1 -ProcessId <int> OR -ProcessName <string> [-ExportHtml]

Parameters:
  -ProcessId      : ID of the process to analyze
  -ProcessName    : Name of the process to analyze
  -ExportHtml     : Optional switch to export detailed HTML report

Example:
  .\script.ps1 -ProcessId 1234
  .\script.ps1 -ProcessName notepad
  .\script.ps1 -ProcessId 1234 -ExportHtml
"@
    exit
}

function Check-AbuseIPDB {
    param([string]$IP, [string]$ApiKey)
    if (-not $IP) { return "Not Found" }
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90"
    $headers = @{ "Key" = $ApiKey; "Accept" = "application/json" }
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        $score = $response.data.abuseConfidenceScore
        $reports = $response.data.totalReports
        $link = "https://www.abuseipdb.com/check/$IP"
        return "Score: $score, Reports: $reports, [Link]($link)"
    }
    catch { return "Lookup failed" }
}

function Check-VirusTotal {
    param([string]$Hash, [string]$ApiKey)
    if (-not $Hash) { return @{Result="Not Found"; Link="N/A"} }
    $url = "https://www.virustotal.com/api/v3/files/$Hash"
    $headers = @{ "x-apikey" = $ApiKey }
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        $malicious = $response.data.attributes.last_analysis_stats.malicious
        $total = $response.data.attributes.last_analysis_stats.total
        $link = "https://www.virustotal.com/gui/file/$Hash/detection"
        return @{ Result = "$malicious / $total detected malicious"; Link = $link }
    }
    catch { return @{ Result = "Lookup failed"; Link = "N/A" } }
}

function Get-GeoIP {
    param([string]$IP)
    if (-not $IP) { return "Not Found" }
    $url = "http://ip-api.com/json/$IP"
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
        if ($response.status -eq "success") {
            return "$($response.country), $($response.regionName), $($response.city)"
        } else { return "Lookup failed" }
    }
    catch { return "Lookup failed" }
}

function Get-ProcessInfo {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )

    if ($ProcessId) {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    elseif ($ProcessName) {
        $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    else {
        Write-Output "Argument missing."
        Show-Help
    }

    if (-not $proc) {
        Write-Output "Process not found."
        exit
    }

    $procId = $proc.Id
    $procName = $proc.ProcessName
    $startTime = $null
    try { $startTime = $proc.StartTime } catch { $startTime = "Not Found" }
    $procPath = (Get-WmiObject Win32_Process -Filter "ProcessId=$procId").ExecutablePath
    if (-not $procPath) { $procPath = "Not Found" }

    $parentProcObj = Get-WmiObject Win32_Process -Filter "ProcessId=$procId"
    $ppid = $parentProcObj.ParentProcessId
    $parentProcPath = (Get-WmiObject Win32_Process -Filter "ProcessId=$ppid").ExecutablePath
    if (-not $parentProcPath) { $parentProcPath = "Not Found" }

    $parentProcName = $null
    try { $parentProcName = (Get-Process -Id $ppid).ProcessName } catch { $parentProcName = "Not Found" }

    $runCount = (Get-Process -Name $procName | Measure-Object).Count

    $procOwner = "Not Found"
    try {
        $ownerInfo = Get-WmiObject Win32_Process -Filter "ProcessId=$procId" | ForEach-Object {
            $result = $_.GetOwner()
            if ($result.ReturnValue -eq 0) { "$($result.Domain)\$($result.User)" }
            else { "Not Found" }
        }
        if ($ownerInfo) { $procOwner = $ownerInfo }
    } catch {}

    $userPrivileges = "Not Implemented" 

    # (SHA256)
    $procHash = "Not Found"
    if (Test-Path $procPath) {
        try {
            $procHash = Get-FileHash -Path $procPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        } catch { $procHash = "Not Found" }
    }

    $vt = Check-VirusTotal -Hash $procHash -ApiKey $VirusTotalApiKey


    $connections = Get-NetTCPConnection -OwningProcess $procId -ErrorAction SilentlyContinue
    $remoteIPs = $connections.RemoteAddress | Where-Object { $_ -ne "0.0.0.0" -and $_ -ne "::" } | Sort-Object -Unique
    $firstIP = $remoteIPs | Select-Object -First 1

    # AbuseIPDB + GeoIP
    $abuseIPDB = Check-AbuseIPDB -IP $firstIP -ApiKey $AbuseIPDBApiKey
    $geoIP = Get-GeoIP -IP $firstIP

    # DLLs
    $dlls = "Not Found"
    try {
        $dlls = (Get-Process -Id $procId).Modules | Select-Object -ExpandProperty ModuleName -ErrorAction Stop
        if (-not $dlls) { $dlls = "Not Found" }
    }
    catch { $dlls = "Not Found" }


    $regKeys = "Not Found"


    $commandLine = "Not Found"
    try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$procId").CommandLine
    }
    catch {}


$jsonOutput = [PSCustomObject]@{
    ProcessId        = $procId
    ProcessName      = $procName
    ParentProcessId  = $ppid
    ParentProcessName= $parentProcName
    ParentProcessPath= $parentProcPath
    StartTime        = $startTime
    ProcessPath      = $procPath
    ProcessHash      = $procHash
    VirusTotal       = $vt.Result
    VirusTotalLink   = $vt.Link
    RemoteIP         = $firstIP
    AbuseIPDB        = $abuseIPDB
    GeoIP            = $geoIP
    DLLs             = $dlls -join ", "
    RegistryKeys     = $regKeys
    User             = $procOwner
    RunCount         = $runCount
    UserPrivileges   = $userPrivileges
    CommandLine      = $commandLine
}


$telegramMessage = @"
    🔍 **Process Analysis Report**

    🆔 Process ID: $procId  
    📛 Process Name: $procName  
    ⏳ Start Time: $startTime  
    🛤️ Process Path: $procPath  
    🧩 Process Hash (SHA256): $procHash  

    👪 Parent Process ID: $ppid  
    📛 Parent Process Name: $parentProcName  
    🛤️ Parent Process Path: $parentProcPath  

    🖥️ User: $procOwner  
    🔐 User Privileges: $userPrivileges  
    🛠️ Run Count: $runCount  

    📡 Network Connection IP: $firstIP  
    🌍 GeoIP Location: $geoIP  
    ⚠️ AbuseIPDB: $abuseIPDB  

    🦠 VirusTotal: $($vt.Result)  
    🔗 VT Link: $($vt.Link)  

    📦 DLLs Loaded:  
    $($dlls -join ", ")  

    🧾 Command Line:  
    $commandLine    
"@


    function Send-TelegramMessage {
        param([string]$message)
        $uri = "https://api.telegram.org/bot$TelegramBotToken/sendMessage"
        $payload = @{
            chat_id = $TelegramChatID
            text = $message
            parse_mode = "Markdown"
        }
        Invoke-RestMethod -Uri $uri -Method Post -Body $payload -ErrorAction SilentlyContinue
    }

    Send-TelegramMessage -message $telegramMessage

    if ($ExportHtml) {
        $htmlContent = $jsonOutput | ConvertTo-Html -Property * -PreContent "<h1>Process Analysis Report</h1>" -PostContent "<footer>Generated by PowerShell Tool</footer>" -Title "Process Report"
        $htmlFile = "$env:TEMP\ProcessReport_$procId.html"
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        Write-Output "HTML Report saved to: $htmlFile"
    }
}


if (-not $ProcessId -and -not $ProcessName) {
    Show-Help
} else {
    Get-ProcessInfo -ProcessId $ProcessId -ProcessName $ProcessName
}
