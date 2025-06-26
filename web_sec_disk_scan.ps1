Function Scan-AppSecuritySettings {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [String]$JsonPath,

        [Parameter(Mandatory = $True)]
        [String]$OutputPath
    )

    Function Get-OsType {
        If ($IsWindows) { Return "Windows" }
        ElseIf ($IsLinux) { Return "Linux" }
        ElseIf ($IsMacOS) { Return "MacOS" }
        Else { Return "Unknown" }
    }

    Function Analyze-Content {
    Param ([String[]]$Lines)

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

    return @{
        Tags = $Tags | Sort-Object -Unique
        MatchedCiphers = $MatchedCiphers
        WeakCiphers = $WeakCiphers
    }
}

    Function Search-ConfigFiles {
        Param ([Array]$Paths)

        $Found = @()
        ForEach ($Path In $Paths) {
            If (Test-Path $Path) {
                Try {
                    $Lines = Get-Content -Path $Path -ErrorAction Stop
                    $Tags = Analyze-Content -Lines $Lines
                    If ($Tags.Count -gt 0) {
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

    Function Search-ConfigInDirectory {
        Param ([String]$DirPath)

        $Results = @()
        If (Test-Path $DirPath) {
            Try {
                $Files = Get-ChildItem -Path $DirPath -Recurse -File -ErrorAction SilentlyContinue
                ForEach ($File In $Files) {
                    Try {
                        $Lines = Get-Content -Path $File.FullName -ErrorAction Stop
                        $Tags = Analyze-Content -Lines $Lines
                        If ($Tags.Count -gt 0) {
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

    Function Search-RegistryKeys {
        Param ([Array]$Paths)

        $Matches = @()
        ForEach ($RegPath In $Paths) {
            If (Test-Path $RegPath) {
                Try {
                    $Item = Get-ItemProperty -Path $RegPath
                    $Text = $Item | Out-String
                    $Lines = $Text -split "`r?`n"
                    $Tags = Analyze-Content -Lines $Lines
                    If ($Tags.Count -gt 0) {
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

    $OsType = Get-OsType
    $Json = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json -Depth 10
    $Report = @()

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
        }
    }

    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
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
            $cmd = "openssl s_client -connect 127.0.0.1:443 $($Probes[$Protocol])"
            $output = & bash -c "$cmd" 2>&1
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
            $CipherOutput = & bash -c "openssl ciphers -v '$CipherString'" 2>&1
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
            $cmd = "openssl s_client -connect 127.0.0.1:443 $($Probes[$Protocol])"
            $output = & bash -c "$cmd" 2>&1
            $Results[$Protocol] = if ($output -match "CONNECTED") { $true } else { $false }
        } catch {
            $Results[$Protocol] = $false
        }
    }

    return $Results
}

Scan-AppSecuritySettings -JsonPath "settings.json" -OutputPath "security_report.json"
