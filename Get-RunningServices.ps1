Param (
    [Parameter(Mandatory = $false)]
    [System.Collections.Generic.HashSet[int]]$ListeningPids = [System.Collections.Generic.HashSet[int]]::new()
)

Function Get-CommandLineByPid {
    Param([int]$ProcID)
    $Platform = & "$PSScriptRoot\Get-OsPlatform.ps1"

    if ($Platform -eq "Windows") {
        try {
            # Use quoted filter to prevent WMI quirks
            $proc = Get-WmiObject Win32_Process -Filter "ProcessId='$ProcID'"
            if ($proc -and $proc.CommandLine) {
                return $proc.CommandLine
            }
            elseif ($proc) {
                return "[CommandLine not available]"
            }
            else {
                return "[No process info found]"
            }
        }
        catch {
            return "[Error: $($_.Exception.Message)]"
        }
    }
    else {
        $Cmd = "/proc/$ProcID/cmdline"
        if (Test-Path $Cmd) {
            try {
                return -join ((Get-Content $Cmd -Raw) -replace "`0", " ")
            }
            catch {
                return "[Error reading /proc]"
            }
        }
        else {
            return "[/proc not available]"
        }
    }
}

Function Get-RunningServices {
    Param (
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.HashSet[int]]$ListeningPids = [System.Collections.Generic.HashSet[int]]::new()
    )

    $Platform = & "$PSScriptRoot\Get-OsPlatform.ps1"
    $Services = @()

    $NetworkKeywords = @(
        'http', 'https', 'nginx', 'apache', 'sql', 'pgsql', 'ftp', 'ssh', 'telnet', 'smtp', 'imap', 'pop3', 
        'ldap', 'dns', 'vpn', 'rdp', 'mysql', 'mongodb', 'mosquitto', 'vault', 'kube', 'grafana', 'prometheus'
    )

    If ($Platform -eq "Windows") {
        $AllServices = Get-WmiObject Win32_Service
        foreach ($Svc in $AllServices) {
            $MatchByPid = $ListeningPids.Contains($Svc.ProcessId)
            $MatchByPath = $false

            if ($Svc.PathName) {
                foreach ($kw in $NetworkKeywords) {
                    if ($Svc.PathName -match $kw) {
                        $MatchByPath = $true
                        break
                    }
                }
            }

            if ($MatchByPid -or $MatchByPath) {
                $Services += [PSCustomObject]@{
                    Name        = $Svc.Name
                    DisplayName = $Svc.DisplayName
                    Status      = $Svc.State
                    PID         = $Svc.ProcessId
                    CommandLine = Get-CommandLineByPid -ProcID $Svc.ProcessId;
                    Hint        = if ($MatchByPid) { "Listening" } else { "Likely networked" }
                }
            }
        }
    }
    Else {
        $PsList = ps aux | Select-Object -Skip 1 | ForEach-Object {
            $line = ($_ -replace '^\s+', '') -replace '\s{2,}', ' '
            $parts = $line -split ' ', 11  # first 10 columns, then command
            if ($parts.Count -ge 11) {
                [PSCustomObject]@{
                    PID  = [int]$parts[1]
                    Unit = $parts[10]
                }
            }
        }




        $Matches = $PsList | Where-Object { $ListeningPids.Contains($_.PID) }

        foreach ($Proc in $Matches) {
            $Services += [PSCustomObject]@{
                Name        = $Proc.Unit
                Status      = "Running"
                PID         = $Proc.PID
                CommandLine = Get-CommandLineByPid -ProcID $Proc.PID;
                Hint        = "Listening"
            }
        }

        # Try to infer additional services with known network functionality
        $Candidates = systemctl list-unit-files --type=service --no-pager | Select-String ".service"
        foreach ($Line in $Candidates) {
            $ServiceName = ($Line -replace '\s+', ' ').Trim().Split(' ')[0]
            foreach ($kw in $NetworkKeywords) {
                if ($ServiceName -match $kw) {
                    if (-not ($Services.Name -contains $ServiceName)) {
                        $Services += [PSCustomObject]@{
                            Name   = $ServiceName
                            Status = "Unknown"
                            PID    = ""
                            Hint   = "Likely networked"
                        }
                    }
                    break
                }
            }
        }
    }

    return $Services
}

# Call function
Get-RunningServices -ListeningPids $ListeningPids
