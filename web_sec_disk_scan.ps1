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
        $Text = $Lines -join "`n"

        If ($Text -match "TLS\s*1\.0") { $Tags += "TLS1.0 (Weak)" }
        If ($Text -match "TLS\s*1\.1") { $Tags += "TLS1.1 (Weak)" }
        If ($Text -match "SSL\s*v3")   { $Tags += "SSLv3 (Insecure)" }
        If ($Text -match "NULL|RC4|DES|3DES|MD5") { $Tags += "Weak Cipher Detected" }
        If ($Text -match "TLS\s*1\.2") { $Tags += "TLS1.2" }
        If ($Text -match "TLS\s*1\.3") { $Tags += "TLS1.3" }
        If ($Text -match "HSTS")       { $Tags += "HSTS" }
        If ($Text -match "CipherSuite") { $Tags += "CipherSuite" }

        return $Tags | Sort-Object -Unique
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
        # If ($Indicators.ContainsKey("RegistryPaths") -and $Indicators.RegistryPaths) {
        If ($Indicators.PSObject.Properties.Name -contains "RegistryPaths" -and $Indicators.RegistryPaths) {

            $FoundRegistry = $Indicators.RegistryPaths | Where-Object { Test-Path $_ }
        }

        $IsInstalled = ($FoundDirs.Count -gt 0 -or $FoundFiles.Count -gt 0 -or $FoundRegistry.Count -gt 0)

        $SecurityFiles = @()
        ForEach ($Dir In $FoundDirs) {
            $SecurityFiles += Search-ConfigInDirectory -DirPath $Dir
        }
        $SecurityFiles += Search-ConfigFiles -Paths $FoundFiles

        $SecurityRegistry = @()
        If ($OsType -eq "Windows" -And $Indicators.ContainsKey("RegistryPaths")) {
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

Scan-AppSecuritySettings -JsonPath "settings.json" -OutputPath "security_report.json"

