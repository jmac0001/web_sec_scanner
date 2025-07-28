
Param()
Function Get-ServerApps {
    Param ([Array]$Apps)
    If (-Not $Apps) { Return @() }

    $Keywords = @(
        "server", "daemon", "mysql", "apache", "nginx", "sql", "postgres", "ftp", "iis",
        "ssh", "vnc", "dns", "smtp", "mosquitto", "mongodb", "vault", "docker", "podman",
        "kube", "grafana", "prometheus"
    )

    Return $Apps | Where-Object {
        If ($_.Name) {
            $Name = $_.Name.ToLower()
            $Keywords | Where-Object { $Name -like "*$_*" } | Measure-Object | Where-Object { $_.Count -gt 0 }
        }
    }
}



# Call function
Get-ServerApps
