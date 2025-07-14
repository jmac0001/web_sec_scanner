function Get-OsType {
    $osPlatform = [System.Environment]::OSVersion.Platform
    If ($osPlatform -eq [System.PlatformID]::Win32NT) { Return "Windows" }
    ElseIf ($osPlatform -eq [System.PlatformID]::Unix) { Return "Linux" }
    ElseIf ($osPlatform -eq [System.PlatformID]::MacOSX) { Return "MacOS" }
    Else { Return "Unknown" }
}

function Analyze-Content {
Param ([String[]]$Lines, $Json)

$Tags = @()
$MatchedCiphers = @()
$WeakCiphers = @()

$Text = $Lines -join "`n"

If ($Text -match "TLS\s*1\.0") { $Tags += "TLS1.0 (Weak)" }
If ($Text -match "TLS\s*1\.1") { $Tags += "TLS1.1 (Weak)" }
If ($Text -match "SSL\s*v3")   { $Tags += "SSLv3 (Insecure)" }
If ($Text -match "TLS\s*1\.2") { $Tags += "TLS1.2" }
If ($Text -match "TLS\s*1\.3") { $Tags += "TLS1.3" }
If ($Text -match "HSTS")       { $Tags += "HSTS" }
If ($Text -match "CipherSuite") { $Tags += "CipherSuite" }

$CipherPattern = "(?i)\b(null|rc4|des|3des|md5|export|low|aes128|aes256|chacha20)\b"
$Matches = [regex]::Matches($Text, $CipherPattern)
ForEach ($Match In $Matches) {
    $MatchedCiphers += $Match.Value.ToUpper()
}

$MatchedCiphers = $MatchedCiphers | Sort-Object -Unique
$WeakTerms = @("NULL", "RC4", "DES", "3DES", "MD5", "EXPORT", "LOW")
$WeakCiphers = $MatchedCiphers | Where-Object { $WeakTerms -contains $_ }

If ($WeakCiphers.Count -gt 0) {
    $Tags += "Weak Cipher Detected"
}

$protocols = Infer-TlsProtocolsFromText -Lines $Lines
$extract = @{}
try {
    $extract = Extract-ProtocolSettingsFromConfig -Lines $Lines
} catch {
    $extract = @{ SslProtocols = ""; CipherString = ""; CipherDetails = @() }
}
$score = Score-SecurityProfile -Protocols $protocols.ActiveProtocols -WeakCiphers $WeakCiphers

$remediations = @()
foreach ($proto in $protocols.ActiveProtocols) {
    $protoItem = $Json.Protocols | Where-Object { $_.protocol -eq $proto }
    if ($protoItem -and $protoItem.remediation_reason -ne "preferred") {
        $remediations += "Protocol $proto is $($protoItem.remediation_reason) $($protoItem.reason). Risk $($protoItem.risk)"
    }
}
if ($WeakCiphers.Count -gt 0) {
    $remediations += "Disable weak ciphers $($WeakCiphers -join ', ')"
}
foreach ($detail in $extract.CipherDetails) {
    if ($detail -match "^(\S+)") {
        $cipherName = $matches[1]
        $cipherItem = $Json.CipherSuites | Where-Object { $_.cipher -eq $cipherName }
        if ($cipherItem -and $cipherItem.risk -in @("weak", "insecure")) {
            $remediations += "Disable cipher $cipherName $($cipherItem.reason). Risk $($cipherItem.risk)"
        }
    }
}
if ($Text -match "CipherSuite|ssl_ciphers|TLS" -and -not ($Text -match "HSTS")) {
    $remediations += "Enable HSTS for secure HTTPS enforcement"
}

return @{
    Tags = $Tags | Sort-Object -Unique
    MatchedCiphers = $MatchedCiphers
    WeakCiphers = $WeakCiphers
    ActiveProtocols = $protocols.ActiveProtocols
    SslProtocols = $extract.SslProtocols
    CipherString = $extract.CipherString
    CipherDetails = $extract.CipherDetails
    Score = $score
    Remediation = $remediations | Select-Object -Unique
}
}

function Search-ConfigFiles {
    Param ([Array]$Paths)

    $Found = @()
    ForEach ($Path In $Paths) {
        If (Test-Path $Path) {
            Try {
                $Lines = Get-Content -Path $Path -ErrorAction Stop
                $Tags = Analyze-Content -Lines $Lines -Json $script:Json
                If ($Tags.Tags.Count -gt 0) {
                    $Found += [PSCustomObject]@{
                        FilePath = $Path
                        Tags     = $Tags
                    }
                }
            } Catch { }
        }
    }
    return $Found
}

function Search-ConfigInDirectory {
    Param ([String]$DirPath)

    $Results = @()
    If (Test-Path $DirPath) {
        Try {
            $Files = Get-ChildItem -Path $DirPath -Recurse -File -ErrorAction SilentlyContinue
            ForEach ($File In $Files) {
                Try {
                    $Lines = Get-Content -Path $File.FullName -ErrorAction Stop
                    $Tags = Analyze-Content -Lines $Lines -Json $script:Json
                    If ($Tags.Tags.Count -gt 0) {
                        $Results += [PSCustomObject]@{
FilePath = $File.FullName
Tags     = $Tags
}
                    }
                } Catch { }
            }
        } Catch { }
    }
    return $Results
}

function Search-RegistryKeys {
    Param ([Array]$Paths)

    $Matches = @()
    ForEach ($RegPath In $Paths) {
        If (Test-Path $RegPath) {
            Try {
                $Item = Get-ItemProperty -Path $RegPath
                $Text = $Item | Out-String
                $Lines = $Text -split "`r?`n"
                $Tags = Analyze-Content -Lines $Lines -Json $script:Json
                If ($Tags.Tags.Count -gt 0) {
                    $Matches += [PSCustomObject]@{
                        RegistryPath = $RegPath
                        Tags         = $Tags
                    }
                }
            } Catch { }
        }
    }
    return $Matches
}

function Scan-AppSecuritySettings {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]$JsonPath,

        [Parameter(Mandatory = $true)]
        [String]$OutputPath
    )

    $OsType = Get-OsType
    $Json = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
    $script:Json = $Json
    $Report = @()

    $extractionCommands = @{
        "Windows Operating System" = @("Get-TlsCipherSuite", "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols /s", "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers /s", "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes /s", "netsh ssl show global")
        "VPN (OpenVPN/WireGuard)" = @("openvpn --show-ciphers", "openvpn --show-tls", "wg show")
        "Windows Registry" = @("reg query HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002", "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols /s")
        "NGINX" = @("nginx -T")
        "Apache Web" = @("apache2ctl -t -D DUMP_RUN_CFG")
        "Apache Tomcat" = @("cat /opt/tomcat/conf/server.xml")
        "Apache .htaccess" = @("find /var/www -name .htaccess -exec cat {} \; | grep -i ssl")
        "PostgreSQL" = @("psql -c `"SHOW ssl;`"", "psql -c `"SHOW ssl_ciphers;`"", "psql -c `"SHOW ssl_min_protocol_version;`"", "psql -c `"SHOW ssl_max_protocol_version;`"")
        "MySQL / MariaDB" = @("mysql -e `"SHOW GLOBAL VARIABLES LIKE '%tls%';`"", "mysql -e `"SHOW GLOBAL VARIABLES LIKE '%ssl%';`"")
        "Node.js / Express" = @("node -p `"require('tls').getCiphers().join('\n')`"")
        "Python / Django / Flask" = @("python -c `"import ssl; print(ssl.OPENSSL_VERSION)`"", "python -c `"import ssl; ctx = ssl.create_default_context(); print([c['name'] for c in ctx.get_ciphers()])`"")
        "SMTP (Postfix/Dovecot)" = @("postconf | grep -i tls", "doveconf | grep -i ssl")
        "Docker/Kubernetes" = @("docker info | grep -i tls", "kubectl get ingress --all-namespaces -o yaml | grep tls")
        "Java" = @("jrunscript -e `"print (java.util.Arrays.asList(javax.net.ssl.SSLServerSocketFactory.getDefault().getSupportedCipherSuites()));`"")
        "OpenSSL" = @("openssl ciphers -v", "openssl version -a")
        "Postfix" = @("postconf | grep -i tls")
        "HAProxy" = @("haproxy -f /etc/haproxy/haproxy.cfg -d")
        "Kubernetes Ingress" = @("kubectl get ingress --all-namespaces -o yaml | grep tls")
        "DotEnv Config" = @("find . -name `".env`" -exec cat {} \; | grep -i tls")
    }

    ForEach ($AppName In $Json.Apps.PSObject.Properties.Name) {
        $App = $Json.Apps.$AppName
        $Indicators = $App.Indicators.OS.$OsType

        If (-Not $Indicators) {
            $Report += @{
                AppName            = $AppName
                OS                 = $OsType
                Installed          = $False
                FoundConfigFiles   = @()
                FoundRegistryKeys  = @()
                ExtractionCommands = $extractionCommands[$AppName]
            }
            Continue
        }

        $FoundDirs  = $Indicators.DirectoryPatterns | Where-Object { Test-Path $_ }
        $FoundFiles = $Indicators.FilePatterns     | Where-Object { Test-Path $_ }

        $FoundRegistry = @()
        If (($Indicators.PSObject.Properties.Name -contains "RegistryPaths") -and $Indicators.RegistryPaths) {
            $FoundRegistry = $Indicators.RegistryPaths | Where-Object { Test-Path $_ }
        }

        $IsInstalled = ($FoundDirs.Count -gt 0 -or $FoundFiles.Count -gt 0 -or $FoundRegistry.Count -gt 0)

        $SecurityFiles = @()
        ForEach ($Dir In $FoundDirs) {
            $SecurityFiles += Search-ConfigInDirectory -DirPath $Dir
        }
        $SecurityFiles += Search-ConfigFiles -Paths $FoundFiles

        $SecurityRegistry = @()
        If ($OsType -eq "Windows" -And ($Indicators.PSObject.Properties.Name -contains "RegistryPaths")) {
            $SecurityRegistry = Search-RegistryKeys -Paths $Indicators.RegistryPaths
        }

        $Report += @{
            AppName           = $AppName
            OS                = $OsType
            Installed         = $IsInstalled
            FoundConfigFiles  = $SecurityFiles
            FoundRegistryKeys = $SecurityRegistry
            ExtractionCommands = $extractionCommands[$AppName]
        }
    }

    $fullReport = @{
        Date = Get-Date -Format "yyyy-MM-dd"
        ComputerName = [System.Net.Dns]::GetHostName()
        Apps = $Report
    }

    $fullReport | ConvertTo-JsonCustom -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "`nScan complete. JSON saved to: $OutputPath"
}

Function Infer-TlsProtocolsFromText {
    Param ([String[]]$Lines)

    $Text = $Lines -join "`n"
    $ActiveProtocols = @()
    $MinProtocol = $null
    $MaxProtocol = $null

    # OpenSSL-style config detection
    If ($Text -match "MinProtocol\s*=\s*(TLSv[0-9.]+)") {
        $MinProtocol = $Matches[1]
    }
    If ($Text -match "MaxProtocol\s*=\s*(TLSv[0-9.]+)") {
        $MaxProtocol = $Matches[1]
    }

    # Apache/Nginx-style config detection
    If ($Text -match "SSLProtocol\s+(.+)") {
        $protoLine = $Matches[1]
        If ($protoLine -notmatch "-TLSv1") { $ActiveProtocols += "TLS1.0" }
        If ($protoLine -notmatch "-TLSv1\.1") { $ActiveProtocols += "TLS1.1" }
        If ($protoLine -notmatch "-TLSv1\.2") { $ActiveProtocols += "TLS1.2" }
        If ($protoLine -notmatch "-TLSv1\.3") { $ActiveProtocols += "TLS1.3" }
    }

    # Registry-style fallback (Windows paths assumed pre-parsed)
    If (-not $ActiveProtocols -and $MinProtocol -and $MaxProtocol) {
        $ActiveProtocols = @($MinProtocol, $MaxProtocol)
    }

    return @{
        MinProtocol = $MinProtocol
        MaxProtocol = $MaxProtocol
        ActiveProtocols = $ActiveProtocols | Sort-Object -Unique
    }
}

Function Test-OpenSslProtocols {
    $Results = @{}
    $Probes = @{
        "TLS1.0" = "-tls1"
        "TLS1.1" = "-tls1_1"
        "TLS1.2" = "-tls1_2"
        "TLS1.3" = "-tls1_3"
    }

    foreach ($Protocol in $Probes.Keys) {
        try {
            $output = openssl s_client -connect 127.0.0.1:443 $($Probes[$Protocol]) 2>&1
            if ($output -match "CONNECTED") {
                $Results[$Protocol] = $true
            } else {
                $Results[$Protocol] = $false
            }
        } catch {
            $Results[$Protocol] = $false
        }
    }
    return $Results
}

Function Score-SecurityProfile {
    Param (
    [String[]]$Protocols,
    [String[]]$WeakCiphers
    )
    $Score = 100
    If ($Protocols -contains "TLS1.0") { $Score -= 30 }
    If ($Protocols -contains "TLS1.1") { $Score -= 20 }
    If ($WeakCiphers.Count -gt 0) { $Score -= ($WeakCiphers.Count * 10) }
    If ($Protocols -notcontains "TLS1.2" -and $Protocols -notcontains "TLS1.3") { $Score -= 25 }
    return [Math]::Max(0, $Score)
}

Function Extract-ProtocolSettingsFromConfig {
    Param ([string[]]$Lines)

    $SslProtocolsLine = $Lines | Where-Object { $_ -match "ssl_protocols" }
    $SslCiphersLine   = $Lines | Where-Object { $_ -match "ssl_ciphers|SSLCipherSuite" }

    $SslProtocols = @()
    if ($SslProtocolsLine) {
        $SslProtocols = ($SslProtocolsLine -split '\s+')[1..($SslProtocolsLine.Length - 1)]
    }

    $CipherString = ""
    if ($SslCiphersLine) {
        $Match = $SslCiphersLine -match "ssl_ciphers\s+(.+)" 
        if ($Match) {
            $CipherString = $Matches[1]
        }
    }

    # Run openssl ciphers if a cipher string was found
    $CipherDetails = @()
    if ($CipherString -and (Get-Command "openssl" -ErrorAction SilentlyContinue)) {
        try {
            $CipherOutput = openssl ciphers -v "$CipherString" 2>&1
            $CipherDetails = $CipherOutput -split "`n"
        } catch {
            $CipherDetails = @("Failed to evaluate cipher string")
        }
    }

    return @{
        SslProtocols   = $SslProtocols -join ", "
        CipherString   = $CipherString
        CipherDetails  = $CipherDetails
    }
}

Function Probe-ProtocolSupport {
    $Results = @{}
    $Probes = @{
        "TLS1.0" = "-tls1"
        "TLS1.1" = "-tls1_1"
        "TLS1.2" = "-tls1_2"
        "TLS1.3" = "-tls1_3"
    }

    foreach ($Protocol in $Probes.Keys) {
        try {
            $output = openssl s_client -connect 127.0.0.1:443 $($Probes[$Protocol]) 2>&1
            $Results[$Protocol] = if ($output -match "CONNECTED") { $true } else { $false }
        } catch {
            $Results[$Protocol] = $false
        }
    }

    return $Results
}

function ConvertTo-JsonCustom {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,
        [int]$Depth = 10
    )

    begin {
        function Convert-Recursive {
            param ($obj, $currentDepth)

            if ($currentDepth -le 0) {
                return '"[Max depth reached]"'
            }

            if ($null -eq $obj) {
                return 'null'
            }

            if ($obj -is [bool]) {
                return $obj.ToString().ToLower()
            }

            if ($obj -is [string]) {
                return '"' + ($obj -replace '\\', '\\' -replace '"', '\"' -replace "\n", '\n' -replace "\r", '\r' -replace "\t", '\t') + '"'
            }

            if ($obj -is [ValueType]) {
                if ($obj -is [decimal] -or $obj -is [double] -or $obj -is [single]) {
                    return $obj.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                } else {
                    return $obj.ToString()
                }
            }

            if ($obj -is [array]) {
                $items = @()
                foreach ($item in $obj) {
                    $items += Convert-Recursive $item ($currentDepth - 1)
                }
                return '[' + ($items -join ',') + ']'
            }

            if ($obj -is [hashtable]) {
                $members = @()
                foreach ($key in $obj.Keys) {
                    $members += '"' + ($key -replace '"', '\"') + '":' + (Convert-Recursive $obj[$key] ($currentDepth - 1))
                }
                return '{' + ($members -join ',') + '}'
            }

            if ($obj -is [pscustomobject]) {
                $members = @()
                foreach ($prop in $obj.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' }) {
                    $members += '"' + ($prop.Name -replace '"', '\"') + '":' + (Convert-Recursive $prop.Value ($currentDepth - 1))
                }
                return '{' + ($members -join ',') + '}'
            }

            # Fallback
            return '"' + ($obj.ToString() -replace '"', '\"') + '"'
        }
    }

    process {
        Convert-Recursive $InputObject $Depth
    }
}

$date = Get-Date -Format "yyyy-MM-dd"
$computerName = [System.Net.Dns]::GetHostName()
$outputPath = "$date-$computerName-web-sec-report.json"
Scan-AppSecuritySettings -JsonPath "settings.json" -OutputPath $outputPath