<#
.SYNOPSIS
'192.168.1.201',
'192.168.1.202',
'192.168.1.203',
'192.168.1.204',
'192.168.1.205't TCP port for TLS protocol and cipher suite support.

.DESCRIPTION
  This script:
    - Tests TLS 1.0 through TLS 1.3
    - Returns the negotiated cipher suite and success/failure
    - Provides basic recommendations for weak or unsupported configurations

.NOTES
  HSTS headers are not checked in this script. Use Invoke-WebRequest to fetch headers manually.

.EXAMPLE
  .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.com" -Port 443
#>



# NOTE: This script does not fetch HTTP headers, so HSTS cannot be validated over raw TLS.
# To check HSTS headers, use curl or Invoke-WebRequest in PowerShell:
# Example:
# $resp = Invoke-WebRequest -Uri "https://yourdomain.com"
# $resp.Headers["Strict-Transport-Security"]

# Load default .NET TLS configuration
Add-Type @"
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
public class TlsTester
{
    public static string TestProtocol(string host, int port, SecurityProtocolType protocol)
    {
        try
        {
            System.Net.ServicePointManager.SecurityProtocol = protocol;
            using (var client = new TcpClient(host, port))
            using (var sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback((s, cert, chain, sslPolicyErrors) => true)))
            {
                sslStream.AuthenticateAsClient(host);
                var cipher = sslStream.CipherAlgorithm.ToString();
                var protocolUsed = sslStream.SslProtocol.ToString();
                return $"{protocolUsed},{cipher},Success";
            }
        }
        catch (AuthenticationException e)
        {
            return $"{protocol},{null},Fail: {e.Message}";
        }
        catch
        {
            return $"{protocol},{null},Fail";
        }
    }
}
"@ -ReferencedAssemblies "System.Net.Security", "System.Security"



$OutputFolder = ".\output"
if (-Not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
}
$Timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$ComputerName = $env:COMPUTERNAME

# Default ports for common services
$DefaultPorts = @{
    "IIS"        = 443
    "NGINX"      = 443
    "Apache"     = 443
    "PostgreSQL" = 5432
    "MySQL"      = 3306
    "MariaDB"    = 3306
    "NodeJS"     = 3000
    "NPM"        = 4873
}

# Input: List of IPs or hostnames to scan
$TargetList = @(
    '192.168.1.201',
    '192.168.1.202',
    '192.168.1.203',
    '192.168.1.204',
    '192.168.1.205'
    # Add more addresses as needed
)

# Combine all default ports into a single array
$PortsToScan = $DefaultPorts.Values | Sort-Object -Unique

# Scan each address on each port
foreach ($Address in $TargetList) {
    foreach ($Port in $PortsToScan) {
        Write-Host "Scanning $Address on port $Port"
        # Existing scanning logic should go here or be updated to use $Address and $Port
    }
}





$OutputCsv = "$OutputFolder\TcpPortTlsScanReport.csv"



# === User Preferred TLS Configuration ===

$UserPreferredProtocols = @("Tls13", "Tls12","TLS 1.3", "TLS 1.2")
$UserPreferredCiphers = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

Write-Host "Preferred TLS protocols: $($UserPreferredProtocols -join ', ')"
Write-Host "Preferred cipher suites: $($UserPreferredCiphers -join ', ')"




# Supported TLS protocols
$ProtocolsToTest = @(
    [Net.SecurityProtocolType]::Tls,
    [Net.SecurityProtocolType]::Tls11,
    [Net.SecurityProtocolType]::Tls12,
    [Net.SecurityProtocolType]::Tls13
)



$Results = @()

foreach ($proto in $ProtocolsToTest) {
    $result = [TlsTester]::TestProtocol($Address, $Port, $proto)
    $split = $result -split ","
    $Results += [PSCustomObject]@{
        Host           = $Address
        Port           = $Port
        Protocol       = $split[0]
        Cipher         = if ($split[1] -eq "") { "N/A" } else { $split[1] }
        Status         = $split[2]
        Recommendation = if ($split[2] -like "*Fail*" -and $proto -eq "Tls") {
            "Insecure (HTTP only or legacy TLS 1.0) - Not recommended"
        }
        elseif ($split[2] -like "*Fail*") {
            "Protocol not supported or blocked"
        }
        elseif ($split[1] -match "RC4|3DES|NULL|EXPORT") {
            "Weak cipher used - update required"
        }
        elseif ($split[0] -eq "Tls13") {
            "Best practice (user preference)"
        }
        else {
            "Acceptable, but TLS 1.3 preferred"
        }
    }
}

$Results | Format-Table -AutoSize
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete. Results saved to: $OutputCsv"

# Scan a web server's port 443
# .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.comsv"

# Scan a web "er er's port 443
# .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.com- -Port 443Port 443
# .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.com" -Port 443

# Scan a web server's port 443
# .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.com" -Port 443