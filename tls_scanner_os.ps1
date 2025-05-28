
param (
    [switch]$Remediate = $false
)


$TimeStamp = $(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss')
$ComputerName = $env:COMPUTERNAME

$BackupRegistryPath = ".\Backup_$ComputerName\Registry_Backup_$TimeStamp.reg"
$BackupConfigPath = ".\Backup_$ComputerName\ConfigFiles_$TimeStamp"

If (-Not (Test-Path $BackupConfigPath)) {
    New-Item -ItemType Directory -Path $BackupConfigPath -Force | Out-Null
}


# === User Preferred Configuration ===

$PreferredProtocols = @("TLS 1.3", "TLS 1.2")  # Ordered list of preferred protocols
$PreferredCipherSuites = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)  # Ordered list of preferred cipher suites


# === User Preferred TLS Configuration ===

$UserPreferredProtocols = @("TLS 1.3", "TLS 1.2")
$UserPreferredCiphers = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

Write-Host "Preferred TLS protocols: $($UserPreferredProtocols -join ', ')"
Write-Host "Preferred cipher suites: $($UserPreferredCiphers -join ', ')"


Write-Host "User-defined preferred protocols: $($PreferredProtocols -join ', ')"
Write-Host "User-defined preferred cipher suites: $($PreferredCipherSuites -join ', ')"


Write-Host "Running in DRY RUN mode. No changes will be made unless -Remediate is specified." -ForegroundColor Yellow



# Unified TLS Configuration Scanner for Windows Systems and Application Configs

$Protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
$BaseKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$FileExtensions = "*.conf", "*.xml", "*.properties", "*.json", "*.yml", "*.ini", "*.cfg", "*.bat", "*.sh"
$Keywords = @("tls", "ssl", "keystore", "truststore", "cipher", "protocol", "javax.net", "https.port", "server.ssl.", "jdk.tls", "enabledProtocols", "cipherSuites", "useStartTLS", "sslSocketFactory", "securityProtocol")

$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }
$Results = @()

Function Get-TlsRegistryStatus {
    Param ([string]$Protocol)

    $ClientPath = "$BaseKey\$Protocol\Client"
    $ServerPath = "$BaseKey\$Protocol\Server"

    $ClientEnabled = Get-ItemProperty -Path $ClientPath -Name "Enabled" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue
    $ServerEnabled = Get-ItemProperty -Path $ServerPath -Name "Enabled" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled -ErrorAction SilentlyContinue

    $ClientState = if ($ClientEnabled -eq $null) { "Not Set" } elseif ($ClientEnabled -eq 0) { "Disabled" } elseif ($ClientEnabled -eq 1) { "Enabled" } else { "Unknown" }
    $ServerState = if ($ServerEnabled -eq $null) { "Not Set" } elseif ($ServerEnabled -eq 0) { "Disabled" } elseif ($ServerEnabled -eq 1) { "Enabled" } else { "Unknown" }

    $Recommendation = switch ($Protocol) {
        "SSL 2.0" {"Disable immediately"}
        "SSL 3.0" {"Disable immediately"}
        "TLS 1.0" {"Deprecated, disable if possible"}
        "TLS 1.1" {"Deprecated, disable if possible"}
        "TLS 1.2" {"Enable if not already"}
        "TLS 1.3" {"Enable if application supports it"}
        default   {"Review manually"}
    }

    $Compatible = if ($Protocol -eq "TLS 1.3") { "Application support required" } else { "Likely supported" }

    [PSCustomObject]@{
                            Technology = Detect-Technology -FilePath $Path
        Source        = "Registry"
        Location      = "SCHANNEL $Protocol"
        Setting       = "$Protocol"
        ClientStatus  = $ClientState
        ServerStatus  = $ServerState
        Recommendation = $Recommendation
        TLS13Compatible = $Compatible
    }
}

Function Get-ConfigRecommendation {
    Param ([string]$Line)

    if ($Line -match "(?i)(TLSv1|TLSv1\.1)") {
        return "Deprecated protocol, remove"
    } elseif ($Line -match "(?i)TLSv1\.2|TLSv1\.3") {
        return "Acceptable protocol"
    } elseif ($Line -match "(?i)cipher.*(NULL|RC4|MD5|EXPORT)") {
        return "Weak cipher, remove"
    } elseif ($Line -match "(?i)keystore|truststore") {
        return "Java security config, review"
    } else {
        return "Review manually"
    }
}

Function Scan-Filesystem {
    foreach ($Drive in $Drives) {
        Get-ChildItem -Path $Drive.Root -Recurse -Include $FileExtensions -ErrorAction SilentlyContinue |
        Where-Object { -Not $_.PSIsContainer } |
        ForEach-Object {
            $Path = $_.FullName
            try {
                $Lines = Get-Content $Path -ErrorAction SilentlyContinue
                for ($i = 0; $i -lt $Lines.Count; $i++) {
                    $Line = $Lines[$i]
                    if ($Keywords | Where-Object { $Line -match $_ }) {
                        $Results += [PSCustomObject]@{
                            Technology = Detect-Technology -FilePath $Path
                            Source         = "File"
                            Location       = "$Path (Line $($i+1))"
                            Setting        = $Line.Trim()
                            ClientStatus   = "-"
                            ServerStatus   = "-"
                            Recommendation = Get-ConfigRecommendation -Line $Line
                            TLS13Compatible = if ($Line -match "TLSv1\.3") { "Yes" } else { "Unknown or No" }
                        }
                    }
                }
            } catch {}
        }
    }
}

Write-Host "Scanning TLS settings in registry and file system..."

# Run registry scan
foreach ($Protocol in $Protocols) {
    $Results += Get-TlsRegistryStatus -Protocol $Protocol
}

# Run filesystem scan
Scan-Filesystem

# Output results
$OutputPath = ".\TLS_Config_Audit_Report.csv"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete. Report saved to: $OutputPath"




# === BEGIN REMEDIATION SECTION ===

# Backup paths
$BackupRegistryPath = ".\Registry_Backup.reg"
$BackupConfigPath = ".\ConfigFile_Backups"

# Create backup folder for configs
If (-Not (Test-Path $BackupConfigPath)) {
    New-Item -ItemType Directory -Path $BackupConfigPath | Out-Null
}

Function Backup-RegistryKey {
    Param([string]$RegKey)
    reg export $RegKey $BackupRegistryPath /y | Out-Null
}

Function Remediate-RegistrySetting {
    Param (
        [string]$Protocol
    )

    $RegPath = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
    Backup-RegistryKey -RegKey "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

    If (-Not (Test-Path "Registry::$RegPath")) {
        New-Item -Path "Registry::$RegPath" -Force | Out-Null
    }

    Set-ItemProperty -Path "Registry::$RegPath" -Name "Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path "Registry::$RegPath" -Name "DisabledByDefault" -Value 1 -Type DWord
}

Function Remediate-ConfigFile {
    Param (
        [string]$FilePath,
        [string]$LineToReplace,
        [string]$Replacement
    )

    $FileName = Split-Path -Path $FilePath -Leaf
    Copy-Item -Path $FilePath -Destination "$BackupConfigPath\$FileName.bak" -Force

    (Get-Content $FilePath) | ForEach-Object {
        if ($_ -match [regex]::Escape($LineToReplace)) {
            $_ -replace [regex]::Escape($LineToReplace), $Replacement
        } else {
            $_
        }
    } | Set-Content $FilePath -Encoding UTF8
}

Function Describe-RemediationReason {
    Param ([string]$Setting)

    switch -Wildcard ($Setting) {
        "*SSL 2.0*" {"SSL 2.0 is deprecated due to known vulnerabilities including POODLE. Source: NIST SP 800-52r2"}
        "*SSL 3.0*" {"SSL 3.0 is deprecated due to POODLE attack vulnerability. Source: NIST SP 800-52r2"}
        "*TLS 1.0*" {"TLS 1.0 is no longer considered secure. Source: PCI-DSS v3.2.1, Microsoft TLS deprecation notice"}
        "*TLS 1.1*" {"TLS 1.1 is deprecated in major browsers and systems. Source: IETF RFC 8996"}
        "*RC4*" {"RC4 cipher is weak and vulnerable to multiple attacks. Source: RFC 7465"}
        "*3DES*" {"3DES provides only 112-bit security and is considered weak. Source: NIST SP 800-57"}
        "*NULL*" {"NULL cipher provides no encryption. Source: OWASP TLS Guidelines"}
        "*EXPORT*" {"EXPORT ciphers are insecure legacy options. Source: IETF TLS working group"}
        default {"This setting is insecure or outdated based on modern security standards."}
    }
}

# Apply automatic remediation based on previous results
foreach ($Result in $Results) {
    if ($Result.Source -eq "Registry" -and $Result.Recommendation -match "Disable") {
        if ($Remediate -and $UserPreferredProtocols -contains $Result.Setting) { Remediate-RegistrySetting -Protocol $Result.Setting } else { Write-Host "Would remediate registry setting: $($Result.Setting)" }
        $Reason = Describe-RemediationReason -Setting $Result.Setting
        Write-Host "Registry protocol $($Result.Setting) remediated. Reason: $Reason"
    }
    elseif ($Result.Source -eq "File" -and $Result.Recommendation -match "remove") {
        $Line = $Result.Setting
        $FilePath = ($Result.Location -split " \(Line")[0]
        $Replacement = "# REMOVED INSECURE SETTING: $Line"
        if ($Remediate) { Remediate-ConfigFile -FilePath $FilePath -LineToReplace $Line -Replacement $Replacement } else { Write-Host "Would remediate config file: $FilePath by replacing: $Line" }
        $Reason = Describe-RemediationReason -Setting $Line
        Write-Host "Config file $FilePath remediated. Reason: $Reason"
    }
}
# === END REMEDIATION SECTION ===


# --- Additional Config Scanner from Universal Engine ---


<#
.SYNOPSIS
  Scans common application config files for TLS/SSL settings and weak ciphers.

.DESCRIPTION
  This engine checks for TLS-related settings in config files from services like:
    - NGINX
    - PostgreSQL
    - MySQL / MariaDB
    - Node.js / Express
    - Python / Django / Flask
    - SMTP servers (Postfix, Dovecot)
    - Docker/Kubernetes mounted configs
    - VPN software (OpenVPN, WireGuard)

  It reports file, line, setting, and recommended action. Results saved as CSV.

.PARAMETER OutputPath
  The path to the CSV file where results will be saved.

.EXAMPLE
  .\Universal-TLS-Engine-Scanner.ps1 -OutputPath .\TlsAuditReport.csv
#>

param (
    [string]$OutputPath = ".\TlsAuditReport.csv"
)

$FilePatterns = "*.conf", "*.ini", "*.env", "*.json", "*.yaml", "*.yml", "*.cnf"
$TLSKeywords = @("ssl", "tls", "cipher", "protocol", "cert", "key", "ca", "dhparam")

$WeakCiphers = @("RC4", "3DES", "NULL", "EXPORT", "DES", "MD5", "TLS_DH_anon", "TLS_RSA_WITH_RC4", "TLS_RSA_WITH_3DES")

$Results = @()


Function Detect-Technology {
    param([string]$FilePath)

    switch -Regex ($FilePath) {
        "nginx.*\.conf"             { return "NGINX" }
        "postgres.*\.conf"          { return "PostgreSQL" }
        "my\.cnf|my\.ini"           { return "MySQL / MariaDB" }
        "node.*\.js|express.*\.js"  { return "Node.js / Express" }
        "flask|django|python.*\.py" { return "Python / Django / Flask" }
        "postfix|dovecot"           { return "SMTP (Postfix/Dovecot)" }
        "docker|k8s|kube|compose"   { return "Docker/Kubernetes" }
        "openvpn|wg0|wireguard"     { return "VPN (OpenVPN/WireGuard)" }
        "httpd\.conf|apache2"       { return "Apache Web" }
        "server\.xml|tomcat"        { return "Apache Tomcat" }
        "java\.security|cacerts"    { return "Java" }
        "system32|schannel|reg"     { return "Windows Operating System" }
        default                     { return "Unknown or Custom" }
    }
}


Function Get-Recommendation {
    param ([string]$line)

    if ($line -match "(?i)TLSv1|TLSv1\.1|SSL") {
        return "Deprecated protocol version used"
    } elseif ($line -match ($WeakCiphers -join "|")) {
        return "Weak cipher suite used"
    } elseif ($line -match "TLSv1\.2|TLSv1\.3") {
        return "Acceptable protocol (prefer TLS 1.3)"
    } elseif ($line -match "http:" -and $line -notmatch "https:") {
        return "Insecure HTTP protocol detected"
    } else {
        return "Potential TLS config - review required"
    }
}

$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }

foreach ($Drive in $Drives) {
    Get-ChildItem -Path $Drive.Root -Recurse -Include $FilePatterns -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        ForEach-Object {
            $Path = $_.FullName
            try {
                $Lines = Get-Content $Path -ErrorAction SilentlyContinue
                for ($i = 0; $i -lt $Lines.Count; $i++) {
                    $Line = $Lines[$i]
                    if ($TLSKeywords | Where-Object { $Line -match $_ }) {
                        $Results += [PSCustomObject]@{
                            Technology = Detect-Technology -FilePath $Path
                            File         = $Path
                            LineNumber   = $i + 1
                            Line         = $Line.Trim()
                            Recommendation = Get-Recommendation -line $Line
                        }
                    }
                }
            } catch { }
        }
}

$Results | Format-Table -AutoSize
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete. Results saved to: $OutputPath"
