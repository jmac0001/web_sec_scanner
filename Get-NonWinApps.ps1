Function Get-CommandOutput {
    Param (
        [String]$Command,
        [Switch]$Json
    )
    Try {
        $Result = Invoke-Expression $Command
        If ($Json) {
            Return $Result | ConvertFrom-Json
        }
        Return $Result
    }
    Catch {
        Return $Null
    }
}

Function Get-NonWinApps {
    $Apps = @()

    If (Get-Command brew -ErrorAction SilentlyContinue) {
        $Apps += brew list --versions | ForEach-Object {
            $Parts = $_ -split ' '
            [PSCustomObject]@{ Name = $Parts[0]; Version = $Parts[1]; Source = "Homebrew" }
        }
    }
    If (Get-Command pip3 -ErrorAction SilentlyContinue) {
        $PipList = Get-CommandOutput "pip3 list --format=json" -Json
        $PipList | ForEach-Object {
            $Apps += [PSCustomObject]@{ Name = $_.name; Version = $_.version; Source = "pip3" }
        }
    }
    If (Get-Command conda -ErrorAction SilentlyContinue) {
        $CondaList = Get-CommandOutput "conda list --json" -Json
        $CondaList | ForEach-Object {
            $Apps += [PSCustomObject]@{ Name = $_.name; Version = $_.version; Source = "conda" }
        }
    }
    If (Get-Command npm -ErrorAction SilentlyContinue) {
        $NpmList = Get-CommandOutput "npm ls -g --depth=0 --json" -Json
        $NpmList.dependencies.Keys | ForEach-Object {
            $Apps += [PSCustomObject]@{ Name = $_; Version = $NpmList.dependencies.$_.version; Source = "npm" }
        }
    }
    If (Get-Command flatpak -ErrorAction SilentlyContinue) {
        $Apps += flatpak list --app --columns=application, version | Select-Object -Skip 1 | ForEach-Object {
            $Split = ($_ -replace '\s+', ' ').Trim().Split(' ')
            [PSCustomObject]@{ Name = $Split[0]; Version = $Split[1]; Source = "flatpak" }
        }
    }
    If (Get-Command snap -ErrorAction SilentlyContinue) {
        $Apps += snap list | Select-Object -Skip 1 | ForEach-Object {
            $Split = ($_ -replace '\s+', ' ').Trim().Split(' ')
            [PSCustomObject]@{ Name = $Split[0]; Version = $Split[1]; Source = "snap" }
        }
    }
    If (Get-Command dpkg -ErrorAction SilentlyContinue) {
        $Apps += dpkg-query -W -f='${Package} ${Version}\n' | ForEach-Object {
            $Parts = $_ -split ' '
            [PSCustomObject]@{ Name = $Parts[0]; Version = $Parts[1]; Source = "dpkg" }
        }
    }
    If (Get-Command rpm -ErrorAction SilentlyContinue) {
        $Apps += rpm -qa --qf '%{NAME} %{VERSION}\n' | ForEach-Object {
            $Parts = $_ -split ' '
            [PSCustomObject]@{ Name = $Parts[0]; Version = $Parts[1]; Source = "rpm" }
        }
    }

    Return $Apps
}

# Call function
Get-NonWinApps
