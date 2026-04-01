using System;
using System.Linq;
using System.Net.NetworkInformation;
using ManagedNativeWifi;

namespace SekuraNetweaver.Modules;

public class WifiAuditor
{
    public string GetStatus()
    {
        try
        {
            // The cleanest way to get the active connection info in ManagedNativeWifi:
            foreach (var interfaceInfo in NativeWifi.EnumerateInterfaces())
            {
                var (result, connectionInfo) = NativeWifi.GetCurrentConnection(interfaceInfo.Id);
                if (result == ActionResult.Success && connectionInfo != null)
                {
                    var ssid = connectionInfo.Ssid.ToString();
                    var auth = connectionInfo.AuthenticationAlgorithm;
                    var cipher = connectionInfo.CipherAlgorithm;

                    var secLabel = GetSecurityLabel(auth, cipher);
                    var indicator = IsNetworkSafe(auth, cipher) ? "✅" : "⚠️";
                    return $"{ssid} · {secLabel} {indicator}";
                }
            }

            // Not on WiFi - fall back to NIC type
            var primaryNic = GetPrimaryInterface();
            if (primaryNic != null)
            {
                return primaryNic.NetworkInterfaceType switch
                {
                    NetworkInterfaceType.Ethernet => "Ethernet Active ✅",
                    NetworkInterfaceType.Ppp => "VPN Active",
                    _ => primaryNic.Name
                };
            }

            return "Not connected";
        }
        catch
        {
            return "Unavailable";
        }
    }

    /// <summary>
    /// Returns a human-readable security label derived from actual auth and cipher algorithms.
    /// </summary>
    private static string GetSecurityLabel(AuthenticationAlgorithm auth, CipherAlgorithm cipher)
    {
        string authStr = auth.ToString().ToUpperInvariant();
        string cipherStr = cipher.ToString().ToUpperInvariant();

        if (authStr.Contains("OPEN") && (cipherStr.Contains("NONE") || cipherStr == "0"))
            return "Open ⚠️";

        if (authStr.Contains("WEP") || cipherStr.Contains("WEP"))
            return "WEP ⚠️";

        if (authStr.Contains("WPA3") || authStr.Contains("SAE") || authStr.Contains("OWE"))
            return "WPA3/OWE";

        if (authStr.Contains("RSNA") || authStr.Contains("WPA2"))
        {
            return cipherStr.Contains("CCMP") || cipherStr.Contains("AES") ? "WPA2" : "WPA2 (weak cipher)";
        }

        if (authStr.Contains("WPA"))
            return "WPA ⚠️";

        return authStr;
    }

    /// <summary>
    /// Returns true if the network uses a currently acceptable encryption standard.
    /// WEP, open, and legacy WPA are considered unsafe.
    /// </summary>
    private static bool IsNetworkSafe(AuthenticationAlgorithm auth, CipherAlgorithm cipher)
    {
        string authStr = auth.ToString().ToUpperInvariant();
        string cipherStr = cipher.ToString().ToUpperInvariant();

        // Unsafe: Open, WEP, or legacy WPA (TKIP)
        if (authStr.Contains("OPEN") && cipherStr.Contains("NONE")) return false;
        if (authStr.Contains("WEP") || cipherStr.Contains("WEP")) return false;
        if (authStr.Contains("WPA") && !authStr.Contains("WPA2") && !authStr.Contains("WPA3") && !authStr.Contains("RSNA")) return false;
        if (cipherStr.Contains("TKIP")) return false;

        return true;
    }

    private static NetworkInterface? GetPrimaryInterface()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.GetIPProperties().GatewayAddresses.Count > 0)
            .OrderByDescending(n => n.Speed)
            .FirstOrDefault();
    }
}
