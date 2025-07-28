
Param()
Function Get-GitHubTools {
    Param ([Array]$Apps)
    Return $Apps | Where-Object { $_.Name -match "(gh|git|github)" }
}

# Call function
Get-GitHubTools
