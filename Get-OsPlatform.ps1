<#

Function Get-OsPlatform {
    If ($IsWindows) { Return "Windows" }
    ElseIf ($IsMacOS) { Return "MacOS" }
    ElseIf ($IsLinux) { Return "Linux" }
    Else { Return "Unknown" }
}

# Call function
Get-OsPlatform
#>


Function Get-OsPlatform {
    Try {
        Add-Type -AssemblyName System.Runtime.InteropServices.RuntimeInformation -ErrorAction Stop
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            return "Windows"
        }
        elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
            return "Linux"
        }
        elseif ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)) {
            return "MacOS"
        }
        else {
            return "Unknown"
        }
    } Catch {
        # Fallback logic for older systems
        $platform = [System.Environment]::OSVersion.Platform
        if ($platform -eq 2) {
            return "Windows"
        }
        elseif ($platform -eq 4 -or $platform -eq 6) {
            return "Unix"
        }
        else {
            return "Unknown"
        }
    }
}

# Call function
Get-OsPlatform


