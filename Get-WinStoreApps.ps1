
Param()
Function Get-WinStoreApps {
    $Apps = @()
    Try {
        $Packages = Get-AppxPackage -ErrorAction SilentlyContinue
        ForEach ($Pkg In $Packages) {
            $Apps += [PSCustomObject]@{
                Name       = $Pkg.Name
                Version    = $Pkg.Version
                Publisher  = $Pkg.Publisher
                Source     = "MicrosoftStore"
            }
        }
    } Catch {}
    Return $Apps
}

# Call function
Get-WinStoreApps
