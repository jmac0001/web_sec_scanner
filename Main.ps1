$Platform = & "$PSScriptRoot\Get-OsPlatform.ps1"
$Apps = @()

Switch ($Platform) {
    "Windows" {
$Apps = @()
$winApps = & "$PSScriptRoot\Get-WinApps.ps1"
$storeApps = & "$PSScriptRoot\Get-WinStoreApps.ps1"
if ($winApps) { $Apps += $winApps }
if ($storeApps) { $Apps += $storeApps }
    }
    "Linux" { $Apps = & "$PSScriptRoot\Get-NonWinApps.ps1" }
    "MacOS" { $Apps = & "$PSScriptRoot\Get-NonWinApps.ps1" }
    Default { Throw "Unsupported platform." }
}

# Load settings.json
$Settings = Get-Content "$PSScriptRoot\settings.json" -Encoding UTF8 | Out-String | ConvertFrom-Json

# Match discovered applications with settings.json
$MatchedApps = foreach ($App in $Apps) {
    $AppName = $App.Name
    if (-not $AppName -and $App -is [string]) {
        $AppName = $App
    }

    # Skip version strings mistakenly treated as app names
    if ($AppName -match '^\d+(\.\d+)*$') {
        continue
    }

    foreach ($Key in $Settings.Apps.PSObject.Properties.Name) {
        if ($AppName -like "*$Key*") {
            $AppInfo = $Settings.Apps.PSObject.Properties[$Key].Value
            [PSCustomObject]@{
                Name            = $AppName
                Version         = $App.Version
                AuditCommand    = $AppInfo.AuditCommand
                AuditConfigFile = $AppInfo.AuditConfigFile
            }
            break
        }
    }
}

# Overwrite $Apps with matched application objects
$Apps = $MatchedApps



$PortInfo = & "$PSScriptRoot\Get-ListeningPorts.ps1"
$PortInfo.Ports = $PortInfo.Ports | Where-Object { $_.CommandLine -and $_.CommandLine.Trim() -ne "" }
$RunningServices = & "$PSScriptRoot\Get-RunningServices.ps1" -ListeningPids $PortInfo.Pids
$RunningServices = $RunningServices | Where-Object { $_.CommandLine -and $_.CommandLine.Trim() -ne "" }

# Get Computer Name in a cross-platform way
if ($Env:COMPUTERNAME) {
    $ComputerName = $Env:COMPUTERNAME
}
elseif ($Env:HOSTNAME) {
    $ComputerName = $Env:HOSTNAME
}
else {
    $ComputerName = hostname
}

# === Associate Ports with RunningServices ===

# Build a map of PID to port(s)
$PidToPorts = @{}
foreach ($port in $PortInfo.Ports) {
    if ($PidToPorts.ContainsKey($port.PID)) {
        $PidToPorts[$port.PID] += , $port
    }
    else {
        $PidToPorts[$port.PID] = @($port)
    }
}

# Attach port info to RunningServices by matching PID
foreach ($svc in $RunningServices) {
    if ($PidToPorts.ContainsKey($svc.PID)) {
        $svc | Add-Member -MemberType NoteProperty -Name Ports -Value $PidToPorts[$svc.PID]
    }
}

# === Heuristically Associate Ports with Applications ===

foreach ($app in $Apps) {
    if (-not $app.Name) { continue }

    $matchedPorts = @()

    foreach ($entry in $PortInfo.Ports) {
        # Heuristic match: look for app name inside process name or command line
        if ($entry.ProcessName -and ($entry.ProcessName -like "*$($app.Name)*")) {
            $matchedPorts += , $entry
        }
        elseif ($entry.CommandLine -and ($entry.CommandLine -like "*$($app.Name)*")) {
            $matchedPorts += , $entry
        }
    }

    if ($matchedPorts.Count -gt 0) {
        $app | Add-Member -MemberType NoteProperty -Name Ports -Value $matchedPorts
    }
}

$Inventory = [PSCustomObject]@{
    Hostname        = $ComputerName
    OS              = $Platform
    ListeningPorts  = $PortInfo.Ports
    Applications    = $Apps
    
    Timestamp       = (Get-Date).ToString("s")
    RunningServices = $RunningServices
    <#
    ServerApps      = Get-ServerApps -Apps $Apps
    GitHubTools     = Get-GitHubTools -Apps $Apps
    
    
    #>
}


# === Prepare Output ===
$DateStr = Get-Date -Format 'yyyy-MM-dd'
$ReportDir = Join-Path $PSScriptRoot 'reports'
If (-Not (Test-Path $ReportDir)) {
    New-Item -Path $ReportDir -ItemType Directory | Out-Null
}
$OutputPath = Join-Path $ReportDir "$($ComputerName)_$($DateStr)_InstalledApps.json"

$Inventory | ConvertTo-Json -Depth 5 | Set-Content $OutputPath -Encoding UTF8
Write-Output "Inventory exported to $OutputPath"

# === Application Auditing Section ===
$AuditResults = @()

function Get-LeastWeakValue {
    param ([string[]]$Values, [string[]]$Preference)
    foreach ($pref in $Preference) {
        foreach ($val in $Values) {
            if ($val -match $pref) {
                return $val
            }
        }
    }
    return $Values[0]
}

$Platform = & "$PSScriptRoot\Get-OsPlatform.ps1"

foreach ($app in $Apps) {
    $AuditEntry = [PSCustomObject]@{
        Name            = $app.Name
        Version         = $app.Version
        AuditCommand    = $app.AuditCommand
        AuditResult     = $null
        AuditConfigFile = $app.AuditConfigFile
    }

    # Select platform-specific AuditCommand if defined as hashtable
    $cmd = $null
    if ($app.AuditCommand -is [Hashtable]) {
        $cmd = $app.AuditCommand[$Platform]
    } else {
        $cmd = $app.AuditCommand
    }

    if ($cmd) {
        try {
            $cmdStr = ($cmd -join ' ') -as [string]
            if ($Platform -eq "Windows") {
                $AuditEntry.AuditResult = cmd /c $cmdStr
            } else {
                $AuditEntry.AuditResult = bash -c $cmdStr
            }
        } catch {
            $AuditEntry.AuditResult = "[Error running AuditCommand: $($_.Exception.Message)]"
        }
    } elseif ($app.AuditConfigFile) {
        $FileInfo = @()
        foreach ($file in $app.AuditConfigFile) {
            if (Test-Path $file) {
                $content = Get-Content $file -Raw

                $tlsMatches = [regex]::Matches($content, '(?i)TLSv[0-9.]+') | ForEach-Object { $_.Value }
                $cipherMatches = [regex]::Matches($content, '(?i)(AES|CHACHA20|3DES|RC4|GCM|CBC)') | ForEach-Object { $_.Value }

                $leastTLS = if ($tlsMatches.Count -gt 0) {
                    Get-LeastWeakValue -Values $tlsMatches -Preference @("TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0")
                } else { $null }

                $leastCipher = if ($cipherMatches.Count -gt 0) {
                    Get-LeastWeakValue -Values $cipherMatches -Preference @("AES", "CHACHA20", "GCM", "CBC", "3DES", "RC4")
                } else { $null }

                $FileInfo += [PSCustomObject]@{
                    FilePath = $file
                    TLS      = $leastTLS
                    Cipher   = $leastCipher
                    HSTS     = if ($content -match '(?i)hsts|strict-transport-security') { "Enabled" } else { "Not Found" }
                }
            } else {
                $FileInfo += [PSCustomObject]@{
                    FilePath = $file
                    TLS      = "[File not found]"
                    Cipher   = "[File not found]"
                    HSTS     = "[File not found]"
                }
            }
        }
        $AuditEntry.AuditResult = $FileInfo
    }

    $AuditResults += $AuditEntry
}

# === Output Audit JSON ===
$AuditOutputPath = Join-Path $ReportDir "$($ComputerName)_$($DateStr)_Audit.json"
$AuditResults | ConvertTo-Json -Depth 5 | Set-Content $AuditOutputPath -Encoding UTF8
Write-Output "Audit data exported to $AuditOutputPath"