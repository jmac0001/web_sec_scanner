# TLS and HSTS Security Scanner - Compatible with PowerShell 5.0

param (
    [ValidateSet("Normal", "Aggressive")][string]$Mode = "Normal",
    [switch]$Report,
    [switch]$Plan,
    [switch]$Backup,
    [string]$Remediate,
    [string]$Backout,
    [switch]$VerifyBackout
)

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

Ensure-Elevation
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
