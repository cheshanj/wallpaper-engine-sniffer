# Wallpaper Engine Risk Monitor
# Logs Wallpaper Engine process, network, and optional Sysmon file events.
# Run from PowerShell:
#   powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1

[CmdletBinding()]
param(
    [int]$PollSeconds = 5,
    [string]$LogRoot = "",
    [switch]$NoPopup,
    [switch]$IncludePrivateNetworkAlerts,
    [switch]$Once
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($LogRoot)) {
    $scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $LogRoot = Join-Path $scriptDirectory "reports"
}

$SuspiciousPorts = @(21, 22, 23, 25, 53, 110, 143, 389, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017)
$ExpectedRemotePorts = @(80, 443, 27015, 27016, 27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025, 27026, 27027, 27028, 27029, 27030, 27031, 27032, 27033, 27034, 27035, 27036, 27037, 27038, 27039, 27040, 27041, 27042, 27043, 27044, 27045, 27046, 27047, 27048, 27049, 27050)
$SensitivePathFragments = @(
    "\Documents\",
    "\Desktop\",
    "\Downloads\",
    "\Pictures\",
    "\Videos\",
    "\OneDrive\",
    "\.ssh\",
    "\AppData\Roaming\Microsoft\Credentials\",
    "\AppData\Roaming\Microsoft\Protect\",
    "\AppData\Local\Google\Chrome\User Data\",
    "\AppData\Roaming\Mozilla\Firefox\Profiles\",
    "\AppData\Roaming\Microsoft\Windows\Recent\"
)

$ExpectedPathFragments = @(
    "\steamapps\common\wallpaper_engine\",
    "\steamapps\workshop\content\431960\",
    "\Steam\userdata\"
)

$SeenConnectionKeys = [System.Collections.Generic.HashSet[string]]::new()
$SeenAlertKeys = [System.Collections.Generic.HashSet[string]]::new()
$KnownWallpaperProcessIds = [System.Collections.Generic.HashSet[int]]::new()
$LastSysmonTime = (Get-Date).AddMinutes(-2)

function Initialize-LogRoot {
    if (-not (Test-Path -LiteralPath $LogRoot)) {
        New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
    }

    $script:EventLogPath = Join-Path $LogRoot "wallpaper-engine-events.jsonl"
    $script:AlertLogPath = Join-Path $LogRoot "wallpaper-engine-alerts.jsonl"
    $script:SummaryPath = Join-Path $LogRoot "latest-summary.txt"
}

function Write-JsonLine {
    param(
        [string]$Path,
        [hashtable]$Object
    )

    $Object.time = (Get-Date).ToString("o")
    ($Object | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath $Path -Encoding UTF8
}

function Show-RiskAlert {
    param(
        [string]$Title,
        [string]$Message,
        [string]$Key = ""
    )

    if ($Key -and $SeenAlertKeys.Contains($Key)) {
        return
    }
    if ($Key) {
        [void]$SeenAlertKeys.Add($Key)
    }

    Write-Warning "$Title - $Message"
    Write-JsonLine -Path $AlertLogPath -Object @{
        type = "alert"
        title = $Title
        message = $Message
        key = $Key
    }

    if ($NoPopup) {
        return
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Media.SystemSounds]::Exclamation.Play()
        [System.Windows.Forms.MessageBox]::Show($Message, $Title, "OK", "Warning") | Out-Null
    }
    catch {
        try {
            msg.exe $env:USERNAME "$Title`n$Message" 2>$null
        }
        catch {
            Write-Host "$Title - $Message"
        }
    }
}

function Test-IsPrivateOrLocalAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    if ($Address -in @("0.0.0.0", "::", "::1", "127.0.0.1")) { return $true }
    if ($Address.StartsWith("127.")) { return $true }
    if ($Address.StartsWith("10.")) { return $true }
    if ($Address.StartsWith("192.168.")) { return $true }
    if ($Address -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    if ($Address.StartsWith("169.254.")) { return $true }
    if ($Address -match "^(fe80|fc|fd)") { return $true }

    return $false
}

function Test-IsExpectedPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $lowerPath = $Path.ToLowerInvariant()
    foreach ($fragment in $ExpectedPathFragments) {
        if ($lowerPath.Contains($fragment.ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Test-IsSensitivePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $lowerPath = $Path.ToLowerInvariant()
    foreach ($fragment in $SensitivePathFragments) {
        if ($lowerPath.Contains($fragment.ToLowerInvariant())) {
            return $true
        }
    }
    return $false
}

function Get-WallpaperProcesses {
    $all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    if (-not $all) { return @() }

    $direct = $all | Where-Object {
        ($_.Name -match "^(wallpaper|wallpaper32|wallpaper64|webwallpaper32|webwallpaper64|ui32|ui64|launcher)\.exe$" -and $_.ExecutablePath -match "\\wallpaper_engine\\") -or
        ($_.ExecutablePath -match "\\steamapps\\common\\wallpaper_engine\\") -or
        ($_.CommandLine -match "wallpaper_engine")
    }

    $ids = @{}
    foreach ($p in $direct) {
        $ids[[int]$p.ProcessId] = $true
    }

    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $all) {
            if ($p.ParentProcessId -and $ids.ContainsKey([int]$p.ParentProcessId) -and -not $ids.ContainsKey([int]$p.ProcessId)) {
                $ids[[int]$p.ProcessId] = $true
                $changed = $true
            }
        }
    }

    $all | Where-Object { $ids.ContainsKey([int]$_.ProcessId) }
}

function Get-DnsNameForAddress {
    param([string]$Address)

    try {
        $match = Get-DnsClientCache -ErrorAction SilentlyContinue |
            Where-Object { $_.Data -eq $Address -or $_.Data -contains $Address } |
            Select-Object -First 1
        if ($match) { return $match.Entry }
    }
    catch { }

    return ""
}

function Watch-WallpaperNetwork {
    param([array]$Processes)

    if (-not $Processes -or $Processes.Count -eq 0) { return }

    $processMap = @{}
    foreach ($p in $Processes) {
        $processMap[[int]$p.ProcessId] = $p
        [void]$KnownWallpaperProcessIds.Add([int]$p.ProcessId)
    }

    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object {
            $processMap.ContainsKey([int]$_.OwningProcess) -and
            $_.RemoteAddress -notin @("0.0.0.0", "::") -and
            $_.State -in @("Established", "SynSent", "CloseWait", "TimeWait")
        }

    foreach ($connection in $connections) {
        $pid = [int]$connection.OwningProcess
        $proc = $processMap[$pid]
        $remoteAddress = [string]$connection.RemoteAddress
        $remotePort = [int]$connection.RemotePort
        $isPrivate = Test-IsPrivateOrLocalAddress -Address $remoteAddress
        $dns = Get-DnsNameForAddress -Address $remoteAddress
        $key = "$pid|$($connection.LocalAddress)|$($connection.LocalPort)|$remoteAddress|$remotePort|$($connection.State)"

        if (-not $SeenConnectionKeys.Contains($key)) {
            [void]$SeenConnectionKeys.Add($key)
            Write-JsonLine -Path $EventLogPath -Object @{
                type = "network"
                processId = $pid
                processName = $proc.Name
                executablePath = $proc.ExecutablePath
                commandLine = $proc.CommandLine
                localAddress = $connection.LocalAddress
                localPort = $connection.LocalPort
                remoteAddress = $remoteAddress
                remotePort = $remotePort
                remoteDnsCacheName = $dns
                state = $connection.State
                isPrivateOrLocal = $isPrivate
            }
        }

        $alertReasons = @()
        if (-not $isPrivate) {
            $alertReasons += "public outbound connection"
        }
        elseif ($IncludePrivateNetworkAlerts) {
            $alertReasons += "private/local network connection"
        }
        if ($SuspiciousPorts -contains $remotePort) {
            $alertReasons += "sensitive remote port $remotePort"
        }
        if (($ExpectedRemotePorts -notcontains $remotePort) -and (-not $isPrivate)) {
            $alertReasons += "unexpected public remote port $remotePort"
        }

        if ($alertReasons.Count -gt 0) {
            $label = if ($dns) { "$remoteAddress ($dns)" } else { $remoteAddress }
            Show-RiskAlert `
                -Title "Wallpaper Engine network activity" `
                -Message "$($proc.Name) PID $pid connected to $label on port ${remotePort}: $($alertReasons -join ', '). Logged at $AlertLogPath" `
                -Key "net|$remoteAddress|$remotePort|$pid"
        }
    }
}

function Watch-WallpaperProcesses {
    param([array]$Processes)

    foreach ($p in $Processes) {
        if (-not $KnownWallpaperProcessIds.Contains([int]$p.ProcessId)) {
            [void]$KnownWallpaperProcessIds.Add([int]$p.ProcessId)
            Write-JsonLine -Path $EventLogPath -Object @{
                type = "process"
                processId = [int]$p.ProcessId
                parentProcessId = [int]$p.ParentProcessId
                processName = $p.Name
                executablePath = $p.ExecutablePath
                commandLine = $p.CommandLine
                user = try { (Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop).User } catch { "" }
            }

            if ((-not (Test-IsExpectedPath -Path $p.ExecutablePath)) -and ($p.ExecutablePath -match "wallpaper|steam|launcher")) {
                Show-RiskAlert `
                    -Title "Wallpaper Engine unusual process path" `
                    -Message "$($p.Name) PID $($p.ProcessId) is running from $($p.ExecutablePath). This is not one of the expected Steam Wallpaper Engine paths." `
                    -Key "procpath|$($p.ProcessId)|$($p.ExecutablePath)"
            }
        }

        if ($p.CommandLine -match "(?i)(powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|bitsadmin|curl|wget|Invoke-WebRequest|Invoke-RestMethod)") {
            Show-RiskAlert `
                -Title "Wallpaper Engine spawned risky command" `
                -Message "$($p.Name) PID $($p.ProcessId) has a risky command line: $($p.CommandLine)" `
                -Key "cmd|$($p.ProcessId)|$($p.CommandLine)"
        }
    }
}

function Get-SysmonProviderName {
    $names = @("Microsoft-Windows-Sysmon/Operational", "Sysmon/Operational")
    foreach ($name in $names) {
        try {
            Get-WinEvent -ListLog $name -ErrorAction Stop | Out-Null
            return $name
        }
        catch { }
    }

    foreach ($name in $names) {
        try {
            $channelPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$name"
            if (Test-Path -LiteralPath $channelPath) {
                return $name
            }
        }
        catch { }
    }

    try {
        $service = Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object -First 1
        if ($service) {
            return "Microsoft-Windows-Sysmon/Operational"
        }
    }
    catch { }

    return ""
}

function Convert-EventXmlData {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $xml = [xml]$Event.ToXml()
    $data = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $data[$node.Name] = $node.'#text'
    }
    return $data
}

function Watch-SysmonEvents {
    param([string]$LogName)

    if (-not $LogName) { return }

    $now = Get-Date
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        StartTime = $LastSysmonTime
        Id = @(1, 3, 11, 15, 22)
    } -ErrorAction SilentlyContinue

    foreach ($event in ($events | Sort-Object TimeCreated)) {
        $data = Convert-EventXmlData -Event $event
        $image = [string]$data.Image
        $parentImage = [string]$data.ParentImage
        $targetFilename = [string]$data.TargetFilename
        $queryName = [string]$data.QueryName
        $destinationIp = [string]$data.DestinationIp
        $destinationPort = [string]$data.DestinationPort

        $isWallpaperEvent =
            $image -match "\\wallpaper_engine\\" -or
            $parentImage -match "\\wallpaper_engine\\" -or
            $data.CommandLine -match "wallpaper_engine"

        if (-not $isWallpaperEvent) {
            continue
        }

        Write-JsonLine -Path $EventLogPath -Object @{
            type = "sysmon"
            eventId = $event.Id
            provider = $LogName
            recordId = $event.RecordId
            eventTime = $event.TimeCreated.ToString("o")
            image = $image
            parentImage = $parentImage
            commandLine = $data.CommandLine
            targetFilename = $targetFilename
            queryName = $queryName
            destinationIp = $destinationIp
            destinationPort = $destinationPort
            raw = $data
        }

        if ($event.Id -in @(11, 15) -and (Test-IsSensitivePath -Path $targetFilename) -and (-not (Test-IsExpectedPath -Path $targetFilename))) {
            Show-RiskAlert `
                -Title "Wallpaper Engine touched a sensitive file path" `
                -Message "$image created or modified $targetFilename. This was captured from Sysmon event $($event.Id)." `
                -Key "file|$image|$targetFilename|$($event.Id)"
        }

        if ($event.Id -eq 22 -and $queryName -and $queryName -notmatch "(?i)(steam|steampowered|steamcontent|wallpaperengine|akamai|cloudflare|microsoft|windows)") {
            Show-RiskAlert `
                -Title "Wallpaper Engine unusual DNS lookup" `
                -Message "$image looked up $queryName. Review whether this belongs to a wallpaper, ad/tracker domain, or unknown offload target." `
                -Key "dns|$image|$queryName"
        }
    }

    $script:LastSysmonTime = $now
}

function Write-LatestSummary {
    param(
        [array]$Processes,
        [string]$SysmonLog
    )

    $lines = @()
    $lines += "Wallpaper Engine Risk Monitor"
    $lines += "Last check: $(Get-Date -Format s)"
    $lines += "Log folder: $LogRoot"
    $lines += "Popup alerts: $(-not $NoPopup)"
    $lines += "Sysmon file/DNS/process enrichment: $(if ($SysmonLog) { "enabled via $SysmonLog" } else { "not available" })"
    $lines += ""

    if (-not $Processes -or $Processes.Count -eq 0) {
        $lines += "No Wallpaper Engine processes detected right now."
    }
    else {
        $lines += "Detected processes:"
        foreach ($p in $Processes) {
            $lines += "  PID $($p.ProcessId) $($p.Name) - $($p.ExecutablePath)"
        }
    }

    $lines += ""
    $lines += "Event log: $EventLogPath"
    $lines += "Alert log: $AlertLogPath"
    $lines | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
}

Initialize-LogRoot
$sysmonLog = Get-SysmonProviderName

Write-Host "Wallpaper Engine Risk Monitor started."
Write-Host "Logs: $LogRoot"
if ($sysmonLog) {
    Write-Host "Sysmon enrichment enabled: $sysmonLog"
}
else {
    Write-Host "Sysmon was not detected. Network/process monitoring still works; exact file-access alerts need Sysmon."
}
Write-Host "Press Ctrl+C to stop."

do {
    $processes = @(Get-WallpaperProcesses)
    Watch-WallpaperProcesses -Processes $processes
    Watch-WallpaperNetwork -Processes $processes
    Watch-SysmonEvents -LogName $sysmonLog
    Write-LatestSummary -Processes $processes -SysmonLog $sysmonLog

    if ($Once) { break }
    Start-Sleep -Seconds $PollSeconds
} while ($true)



