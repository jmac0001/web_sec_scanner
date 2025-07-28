Param (
    [Parameter(Mandatory = $True)][String]$Command,
    [Parameter(Mandatory = $True)][String]$Json
)

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

Get-CommandOutput -Command $Command -Json $Json