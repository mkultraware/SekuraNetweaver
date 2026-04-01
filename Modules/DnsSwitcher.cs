using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;

namespace SekuraNetweaver.Modules;

public class DnsSwitcher
{
    public static readonly Dictionary<string, string[]> Providers = new()
    {
        { "Cloudflare", new[] { "1.1.1.1", "1.0.0.1" } },
        { "Quad9",      new[] { "9.9.9.9", "149.112.112.112" } },
        { "Google",     new[] { "8.8.8.8", "8.8.4.4" } },
        { "Original",   Array.Empty<string>() },
    };

    // Stores the original DNS config per adapter SettingID (GUID).
    // Using SettingID ties us to WMI, which is locale-independent.
    private record DnsConfig(string[] Servers, bool IsDhcp);
    private readonly Dictionary<string, DnsConfig> _originalDns = new();

    public string CurrentProvider { get; private set; } = "Unknown";

    public DnsSwitcher()
    {
        CacheAllOriginalDns();
        CurrentProvider = DetectCurrentProvider();
    }

    public void SwitchTo(string providerName)
    {
        if (!Providers.ContainsKey(providerName)) return;

        foreach (var adapter in GetActiveAdapters())
        {
            if (providerName == "Original")
                RestoreOriginalDns(adapter.settingId);
            else if (Providers.TryGetValue(providerName, out var servers))
                SetDnsServersWmi(adapter.settingId, servers);
        }

        CurrentProvider = providerName;
    }

    private void CacheAllOriginalDns()
    {
        foreach (var adapter in GetActiveAdapters())
        {
            var config = ReadDnsConfig(adapter.settingId);
            _originalDns[adapter.settingId] = config;
        }
    }

    private void RestoreOriginalDns(string settingId)
    {
        if (!_originalDns.TryGetValue(settingId, out var config)) return;

        if (config.IsDhcp)
        {
            // Passing null/empty to SetDNSServerSearchOrder restores DHCP-assigned DNS
            SetDnsServersWmi(settingId, null);
        }
        else
        {
            SetDnsServersWmi(settingId, config.Servers);
        }
    }

    /// <summary>
    /// Reads current DNS config using the .NET NetworkInterface API.
    /// Locale-independent — no netsh string parsing.
    /// </summary>
    private static DnsConfig ReadDnsConfig(string settingId)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => string.Equals(n.Id, settingId, StringComparison.OrdinalIgnoreCase));

        if (nic == null) return new DnsConfig(Array.Empty<string>(), false);

        var props = nic.GetIPProperties();
        var servers = props.DnsAddresses
            .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Select(a => a.ToString())
            .ToArray();

        // Determine DHCP via WMI — NetworkInterface doesn't expose this directly
        bool isDhcp = IsDhcpEnabled(settingId);

        return new DnsConfig(servers, isDhcp);
    }

    private static bool IsDhcpEnabled(string settingId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{settingId}'");
            foreach (ManagementObject obj in searcher.Get())
                return (bool)(obj["DHCPEnabled"] ?? false);
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Sets DNS servers via WMI Win32_NetworkAdapterConfiguration.
    /// Faster and more reliable than netsh — no process spawn, no string parsing,
    /// no locale dependency.
    /// Pass null or empty array to restore DHCP-assigned DNS.
    /// </summary>
    private static void SetDnsServersWmi(string settingId, string[]? servers)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{settingId}'");

            foreach (ManagementObject obj in searcher.Get())
            {
                // null or empty array = let DHCP manage DNS
                var param = (servers == null || servers.Length == 0)
                    ? null
                    : servers;

                obj.InvokeMethod("SetDNSServerSearchOrder", new object?[] { param });
            }
        }
        catch { }
    }

    public bool IsDoHEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\DoHServers");
            return key != null;
        }
        catch { return false; }
    }

    private string DetectCurrentProvider()
    {
        var primary = GetActiveAdapters().FirstOrDefault();
        if (primary == default) return "Unknown";

        var config = ReadDnsConfig(primary.settingId);
        foreach (var kvp in Providers)
        {
            if (kvp.Value.Intersect(config.Servers).Any())
                return kvp.Key;
        }
        return "Custom/Original";
    }

    /// <summary>
    /// Returns (name, settingId) for all active non-loopback adapters with a gateway.
    /// SettingID is the adapter GUID — the stable cross-API identifier that maps
    /// NetworkInterface to Win32_NetworkAdapterConfiguration.
    /// </summary>
    private static List<(string name, string settingId)> GetActiveAdapters()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.GetIPProperties().GatewayAddresses.Count > 0)
            .Select(n => (n.Name, n.Id))
            .ToList();
    }
}
