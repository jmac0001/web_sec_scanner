
Param()
Function Get-CommandLineByPid {
    Param([int]$ProcID)
    $Platform = & "$PSScriptRoot\\Get-OsPlatform.ps1"

    if ($Platform -eq "Windows") {
        try {
            return (Get-CimInstance Win32_Process -Filter "ProcessId=$ProcID").CommandLine
        } catch { return $null }
    } else {
        $Cmd = "/proc/$ProcID/cmdline"
        if (Test-Path $Cmd) {
            try {
                return -join ((Get-Content $Cmd -Raw) -replace "`0", " ")
            } catch { return $null }
        } else {
            return $null
        }
    }
}

Function Get-ListeningPorts {
    $Platform =  & "$PSScriptRoot\Get-OsPlatform.ps1"
    $Ports = @()
    $PidSet = New-Object 'System.Collections.Generic.HashSet[Int32]'

    If ($Platform -eq "Windows") {
        $Netstat = netstat -ano | Select-String "LISTENING"
        ForEach ($Line In $Netstat) {
            $Tokens = ($Line -replace '\s+', ' ').Trim().Split(' ')
            $ProcId = [int]$Tokens[-1]
            $PidSet.Add($ProcId) | Out-Null
            $Ports += [PSCustomObject]@{
                Protocol     = $Tokens[0]
                LocalAddress = $Tokens[1]
                PID          = $ProcId;
                    CommandLine = Get-CommandLineByPid($ProcId)
                State        = "LISTENING"
            }
        }
    } Else {
        $SsOutput = ss -lntupH 2>$Null
        ForEach ($Line in $SsOutput) {
            $Fields = ($Line -replace '\s+', ' ').Split(' ')
if ($Fields[-1] -match 'pid=(\d+)') {
                $PidSet.Add($ProcId) | Out-Null
                $Ports += [PSCustomObject]@{
                    Protocol     = $Fields[0]
                    LocalAddress = $Fields[4]
                    PID          = $ProcId;
                    CommandLine = Get-CommandLineByPid(Pid = $ProcId)
                    State        = $Fields[1]
                }
            }
        }
    }

    return @{ Pids = $PidSet; Ports = $Ports }
}


# Call function
Get-ListeningPorts