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
            var primaryNic = GetPrimaryInterface();
            if (primaryNic != null)
            {
                var ssids = NativeWifi.EnumerateConnectedNetworkSsids();
                var ssid = ssids.FirstOrDefault()?.ToString();
                
                if (!string.IsNullOrEmpty(ssid))
                {
                    var auth = GetAuthType(ssid);
                    var secure = IsNetworkSafe(ssid) ? "✅" : "⚠️";
                    return $"WiFi: {ssid} · {auth} {secure}";
                }
                
                var nicType = primaryNic.NetworkInterfaceType switch
                {
                    NetworkInterfaceType.Ethernet => "Ethernet Active ✅",
                    NetworkInterfaceType.Wireless80211 => "WiFi Active",
                    NetworkInterfaceType.Ppp => "VPN Active",
                    _ => $"{primaryNic.Name}"
                };
                return nicType;
            }
            
            return "Not connected";
        }
        catch
        {
            return "Unavailable";
        }
    }

    private static bool IsNetworkSafe(string ssid)
    {
        try
        {
            var bssNetworks = NativeWifi.EnumerateBssNetworks();
            foreach (var bss in bssNetworks)
            {
                if (bss.Ssid.ToString() != ssid) continue;

                var phy = bss.PhyType.ToString();
                // Modern standards = safe
                if (phy.Contains("Ac") || phy.Contains("Ax") || phy.Contains("6") || phy.Contains("7"))
                    return true;
                
                // N = safe if not ancient
                if (phy.Contains("N"))
                    return true;
                    
                return false;
            }
        }
        catch { }
        return false;
    }

    private static string GetAuthType(string ssid)
    {
        try
        {
            var bssNetworks = NativeWifi.EnumerateBssNetworks();
            foreach (var bss in bssNetworks)
            {
                if (bss.Ssid.ToString() != ssid) continue;

                var phy = bss.PhyType.ToString();
                return phy switch
                {
                    var t when t.Contains("Ac") || t.Contains("Ax") => "WPA2/WPA3",
                    var t when t.Contains("N")   => "WPA2",
                    var t when t.Contains("G")   => "WPA/WEP ⚠️",
                    var t when t.Contains("6") || t.Contains("7") => "WiFi 6/7",
                    _                            => phy
                };
            }
        }
        catch { }
        return "Unknown";
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

