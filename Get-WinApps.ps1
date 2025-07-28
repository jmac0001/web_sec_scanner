
Param()
Function Get-WinApps {
    $Apps = @()
    $RegistryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    ForEach ($Path In $RegistryPaths) {
        Try {
            $Items = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
            ForEach ($Item In $Items) {
                $Apps += [PSCustomObject]@{
                    Name        = $Item.DisplayName
                    Version     = $Item.DisplayVersion
                    Publisher   = $Item.Publisher
                    InstallDate = $Item.InstallDate
                    Source      = "Registry"
                }
            }
        } Catch {}
    }
    Return $Apps
}

# Call function
Get-WinApps
