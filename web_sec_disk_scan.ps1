Function Find-InstalledApps {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [String]$JsonPath
    )

    Function Get-OsType {
        If ($IsWindows) { Return "Windows" }
        ElseIf ($IsLinux) { Return "Linux" }
        ElseIf ($IsMacOS) { Return "MacOS" }
        Else { Return "Unknown" }
    }

    Function Test-RegistryPaths {
        Param (
            [Array]$RegistryPaths
        )
        $Found = @()
        ForEach ($Path In $RegistryPaths) {
            If (Test-Path $Path) {
                $Found += $Path
            }
        }
        Return $Found
    }

    $OsType = Get-OsType
    If ($OsType -eq "Unknown") {
        Write-Warning "Unsupported Operating System"
        Return
    }

    Try {
        $Json = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json -Depth 10
    }
    Catch {
        Write-Error "Failed to parse JSON: $_"
        Return
    }

    $Results = @()

    ForEach ($AppName In $Json.Apps.PSObject.Properties.Name) {
        $App = $Json.Apps.$AppName
        $Indicators = $App.Indicators.OS.$OsType

        $FoundDirs = @()
        $FoundFiles = @()
        $FoundRegistry = @()

        If ($Indicators) {
            ForEach ($Dir In $Indicators.DirectoryPatterns) {
                If (Test-Path $Dir) { $FoundDirs += $Dir }
            }

            ForEach ($File In $Indicators.FilePatterns) {
                If (Test-Path $File) { $FoundFiles += $File }
            }

            If ($OsType -eq "Windows" -And $Indicators.ContainsKey("RegistryPaths")) {
                $FoundRegistry = Test-RegistryPaths -RegistryPaths $Indicators.RegistryPaths
            }
        }

        $IsInstalled = ($FoundDirs.Count -gt 0 -or $FoundFiles.Count -gt 0 -or $FoundRegistry.Count -gt 0)

        $Results += [PSCustomObject]@{
            AppName     = $AppName
            OS          = $OsType
            Installed   = $IsInstalled
            Directories = ($FoundDirs -join "; ")
            Files       = ($FoundFiles -join "; ")
            Registry    = ($FoundRegistry -join "; ")
        }
    }

    Return $Results
}



$results = Find-InstalledApps -JsonPath "settings.json"

$results | Export-Csv -Path "installed_apps.csv" -NoTypeInformation -Force -Encoding UTF8


