
param (
    [string]$Host,
    [int]$Port = 443,
    [string]$OutputCsv = ".\TcpPortTlsScanReport.csv"
)


# === User Preferred TLS Configuration ===

$UserPreferredProtocols = @("Tls13", "Tls12")
$UserPreferredCiphers = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)


# === User Preferred TLS Configuration ===

$UserPreferredProtocols = @("TLS 1.3", "TLS 1.2")
$UserPreferredCiphers = @(
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
)

Write-Host "Preferred TLS protocols: $($UserPreferredProtocols -join ', ')"
Write-Host "Preferred cipher suites: $($UserPreferredCiphers -join ', ')"


Write-Host "Preferred TLS protocols: $($UserPreferredProtocols -join ', ')"
Write-Host "Preferred cipher suites: $($UserPreferredCiphers -join ', ')"


# Supported TLS protocols
$ProtocolsToTest = @(
    [Net.SecurityProtocolType]::Tls,
    [Net.SecurityProtocolType]::Tls11,
    [Net.SecurityProtocolType]::Tls12,
    [Net.SecurityProtocolType]::Tls13
)

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

$Results = @()

foreach ($proto in $ProtocolsToTest) {
    $result = [TlsTester]::TestProtocol($Host, $Port, $proto)
    $split = $result -split ","
    $Results += [PSCustomObject]@{
        Host        = $Host
        Port        = $Port
        Protocol    = $split[0]
        Cipher      = if ($split[1] -eq "") { "N/A" } else { $split[1] }
        Status      = $split[2]
        Recommendation = if ($split[2] -like "*Fail*" -and $proto -eq "Tls") {
                            "Insecure (HTTP only or legacy TLS 1.0) - Not recommended"
                         } elseif ($split[2] -like "*Fail*") {
                            "Protocol not supported or blocked"
                         } elseif ($split[1] -match "RC4|3DES|NULL|EXPORT") {
                            "Weak cipher used - update required"
                         } elseif ($split[0] -eq "Tls13") {
                            "Best practice (user preference)"
                         } else {
                            "Acceptable, but TLS 1.3 preferred"
                         }
    }
}

$Results | Format-Table -AutoSize
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "Scan complete. Results saved to: $OutputCsv"

# Scan a web server's port 443
# .\Scan-TlsSettings-OnTcpPort.ps1 -Host "example.com" -Port 443


