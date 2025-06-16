param (
    [ValidateSet("Normal", "Aggressive")][string]$Mode = "Normal",
    [switch]$Report,
    [switch]$Plan,
    [switch]$Backup,
    [string]$Remediate,
    [string]$Backout,
    [switch]$VerifyBackout
)



function Log-Verbose {
    param([string]$Message)
    if ($VerbosePreference -eq 'Continue') {
        Write-Host "[VERBOSE] $Message" -ForegroundColor Cyan
    }
    Add-Content -Path "$PSScriptRoot\Output\script.log" -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") [VERBOSE] $Message"
}



function Get-OperatingSystem {
    if ($env:OS -like "*Windows*") { return "Windows" }
    elseif (Test-Path "/etc/os-release") { return "Linux" }
    else { return "Unknown" }
}

function Get-Volumes {
    if ($env:OS -like "*Windows*") {
        return Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 } | Select-Object -ExpandProperty Root
    } else {
        return @("/", "/mnt", "/opt", "/home")
    }
}

function Load-Settings {
    return Get-Content "$PSScriptRoot/settings.json" -Raw | ConvertFrom-Json
}

function Log-Action {
    param($Message)
    $TimeStamp = Get-Date -Format o
    $LogFile = "$PSScriptRoot/security_scan.log"
    "$TimeStamp [$env:COMPUTERNAME] [$env:USERNAME] $Message" | Out-File -Append $LogFile
}

function Search-Applications {
    param ($Settings, $Mode, $OsType, $Volumes)
    $Discovered = @()
    $NotDiscovered = @()
    $Apps = $Settings.OS[$OsType].Apps

    foreach ($App in $Apps) {
        $Found = $false
        if ($Mode -eq "Normal") {
            $Paths = @($App.InstallPath) + @($App.ConfigPath)
            foreach ($Vol in $Volumes) {
                foreach ($Path in $Paths) {
                    if ($null -ne $Path -and $Path -ne "") {
                        $Expanded = $Path -replace "%VOLUME%", $Vol
                        if (Test-Path $Expanded) {
                            $Found = $true
                        }
                    }
                }
            }
        } elseif ($Mode -eq "Aggressive") {
            foreach ($Vol in $Volumes) {
                Get-ChildItem -Path $Vol -Recurse -Include *.conf,*.xml,*.ini -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($Keyword in $App.Keywords) {
                        if ((Get-Content $_.FullName -ErrorAction SilentlyContinue | Select-String -Pattern $Keyword)) {
                            $Found = $true
                        }
                    }
                }
            }
        }
        if ($Found) {
            $Discovered += New-Object PSObject -Property @{
                App       = $App.FriendlyName
                OS        = $OsType
                Status    = "Found"
                TLS       = $App.Recommendations.TLS
                HSTS      = $App.Recommendations.HSTS
            }
        } else {
            $NotDiscovered += New-Object PSObject -Property @{
                App    = $App.FriendlyName
                OS     = $OsType
                Status = "Missing"
            }
        }
    }
    return @{ Discovered = $Discovered; NotDiscovered = $NotDiscovered }
}


function Export-Report {
    param ($Results, $OutputDir)
    
$Timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName) { $ComputerName = $(hostname) }

    $ReportFile = Join-Path $OutputDir "$Timestamp-$ComputerName-report.csv"
    $Results.Discovered + $Results.NotDiscovered | Export-Csv -Path $ReportFile -NoTypeInformation
    Log-Action "Report generated at $ReportFile"
}



function Export-Plan {
    param ($Results, $OutputDir)
    
$Timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName) { $ComputerName = $(hostname) }

    $PlanFile = Join-Path $OutputDir "$Timestamp-$ComputerName-plan.json"
    $Results.Discovered | ConvertTo-Json -Depth 5 | Out-File $PlanFile
    Log-Action "Plan created at $PlanFile"
    return $PlanFile
}



function Perform-Backup {
    param ($PlanFile, $OutputDir)
    
$Timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$ComputerName = $env:COMPUTERNAME
if (-not $ComputerName) { $ComputerName = $(hostname) }

    $ZipFile = Join-Path $OutputDir "$Timestamp-$ComputerName-backup.zip"
    Compress-Archive -Path $PlanFile, "$OutputDir\*.csv" -DestinationPath $ZipFile -Force
    Log-Action "Backup created at $ZipFile"
    return $ZipFile
}


function Remediate-System {
    param ($PlanFile)
    $Plan = Get-Content $PlanFile | ConvertFrom-Json
    foreach ($App in $Plan) {
        Log-Action "Remediating $($App.App)..."
        foreach ($Path in $App.ConfigPath) {
            if ($env:OS -like "*Windows*" -and $Path -like 'HKLM:*') {
                $BackupPath = "$PSScriptRoot/registry-backup-$($App.App.Replace(' ','_')).reg"
                reg export $Path $BackupPath /y | Out-Null
                Set-ItemProperty -Path $Path -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            } elseif (Test-Path $Path) {
                $Content = Get-Content $Path -Raw
                if ($Content -notmatch "Strict-Transport-Security") {
                    Add-Content -Path $Path -Value "`n# Enforce HSTS`nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains";"
                }
            }
        }
    }
    Log-Action "Remediation completed"
}

function Backout-System {
    param ($BackupZip)
    $Temp = Join-Path $env:TEMP "Restore_$(Get-Random)"
    Expand-Archive -Path $BackupZip -DestinationPath $Temp -Force
    Log-Action "Restoring from backup $BackupZip"
    Get-ChildItem -Path $Temp -Filter *.reg | ForEach-Object {
        reg import $_.FullName | Out-Null
        Log-Action "Restored registry from $($_.Name)"
    }
    Log-Action "Backout completed"
}






function Generate-BackoutVerificationReport {
    param ($BackupZip)
    $TempPath = Join-Path $env:TEMP "Verify_$(Get-Random)"
    Expand-Archive -Path $BackupZip -DestinationPath $TempPath -Force
    $Report = @()
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = "$PSScriptRoot/Output/$env:COMPUTERNAME-backout-verify-$TimeStamp.csv"

    Get-ChildItem -Path $TempPath -Filter *.reg | ForEach-Object {
        $BaseName = $_.BaseName -replace "registry-backup-", ""
        $AppName = $BaseName -replace "_", " "
        $RegPathLine = ($_ | Get-Content | Select-String -Pattern '\[.*\]' | Select-Object -First 1).ToString()
        $RegKeyPath = $RegPathLine -replace '[\[\]]', ''
        $KeyStatus = if (Test-Path "Registry::$RegKeyPath") { 'Restored' } else { 'Missing' }

        $ValueStatus = 'N/A'
        if ($KeyStatus -eq 'Restored') {
            try {
                $KeyProps = Get-ItemProperty -Path "Registry::$RegKeyPath" -ErrorAction Stop
                if (($KeyProps | Get-Member -Name 'Enabled')) {
                    $ValueStatus = if ($KeyProps.Enabled -eq 0) { 'Correct' } else { 'Incorrect' }
                } else {
                    $ValueStatus = 'Missing Value'
                }
            } catch {
                $ValueStatus = 'Error Reading Key'
            }
        }

        $Report += New-Object PSObject -Property @{
            Application       = $AppName
            RegistryBackup    = $_.Name
            RegistryKey       = $RegKeyPath
            RegistryRestored  = $KeyStatus
            EnabledValue      = $ValueStatus
            Status            = 'Backup Exists'
        }
    }

    $Report | Export-Csv -Path $ReportPath -NoTypeInformation
    Log-Action "Backout verification report generated at $ReportPath"
}

$OsType = Get-OperatingSystem
$Volumes = Get-Volumes
$Settings = Load-Settings
$OutputDir = "$PSScriptRoot\Output"
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

if ($Remediate) {
    Remediate-System -planFile $Remediate
} elseif ($Backout) {
    Backout-System -backupZip $Backout
} elseif ($VerifyBackout) {
    $LatestBackup = Get-ChildItem "$OutputDir" -Filter "*-backup.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -ne $LatestBackup) {
        Generate-BackoutVerificationReport -BackupZip $LatestBackup.FullName
    } else {
        Write-Host "No backup ZIP found for verification." -ForegroundColor Yellow
    }
} else {
    $Results = Search-Applications -Settings $Settings -Mode $Mode -OsType $OsType -Volumes $Volumes
    if ($Report) { Export-Report -Results $Results -OutputDir $OutputDir }
    if ($Plan) { $PlanFile = Export-Plan -Results $Results -OutputDir $OutputDir }
    if ($Backup) {
        $PlanFile = Export-Plan -Results $Results -OutputDir $OutputDir
        Export-Report -Results $Results -OutputDir $OutputDir
        Perform-Backup -PlanFile $PlanFile -OutputDir $OutputDir
    }
}
