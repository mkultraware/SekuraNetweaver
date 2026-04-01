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
            // EnumerateAvailableNetworks gives us actual security info (auth + cipher).
            // EnumerateBssNetworks only gives PhyType (802.11a/b/g/n/ac/ax) which is
            // the radio standard, NOT the encryption standard. The two are unrelated.
            var connectedNetworks = NativeWifi.EnumerateAvailableNetworks()
                .Where(n => n.IsConnected)
                .ToList();

            if (connectedNetworks.Any())
            {
                var network = connectedNetworks.First();
                var ssid = network.Ssid.ToString();
                var secLabel = GetSecurityLabel(network.AuthAlgorithm, network.CipherAlgorithm);
                var indicator = IsNetworkSafe(network.AuthAlgorithm, network.CipherAlgorithm) ? "✅" : "⚠️";
                return $"{ssid} · {secLabel} {indicator}";
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
    private static string GetSecurityLabel(AuthAlgorithm auth, CipherAlgorithm cipher)
    {
        // Open network - no encryption
        if (auth == AuthAlgorithm.Open && cipher == CipherAlgorithm.None)
            return "Open ⚠️";

        // WEP - deprecated, broken
        if (cipher is CipherAlgorithm.Wep40 or CipherAlgorithm.Wep104 or CipherAlgorithm.Wep)
            return "WEP ⚠️";

        // WPA3
        if (auth is AuthAlgorithm.Wpa3Sae or AuthAlgorithm.Wpa3)
            return "WPA3";

        // OWE (Opportunistic Wireless Encryption - open but encrypted)
        if (auth == AuthAlgorithm.Owe)
            return "OWE";

        // WPA2 - RSNA with CCMP/AES
        if (auth is AuthAlgorithm.Rsna or AuthAlgorithm.RsnaPsk)
            return cipher == CipherAlgorithm.Ccmp ? "WPA2" : "WPA2 (weak cipher)";

        // WPA - legacy
        if (auth is AuthAlgorithm.Wpa or AuthAlgorithm.WpaPsk)
            return "WPA ⚠️";

        // Unknown or vendor-specific
        return $"{auth}";
    }

    /// <summary>
    /// Returns true if the network uses a currently acceptable encryption standard.
    /// WEP, open, and legacy WPA are considered unsafe.
    /// </summary>
    private static bool IsNetworkSafe(AuthAlgorithm auth, CipherAlgorithm cipher)
    {
        // Open with no encryption
        if (auth == AuthAlgorithm.Open && cipher == CipherAlgorithm.None) return false;

        // WEP is cryptographically broken
        if (cipher is CipherAlgorithm.Wep40 or CipherAlgorithm.Wep104 or CipherAlgorithm.Wep) return false;

        // WPA (TKIP) - deprecated, crackable
        if (auth is AuthAlgorithm.Wpa or AuthAlgorithm.WpaPsk) return false;

        // WPA2 or better with AES-CCMP or stronger = safe
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
