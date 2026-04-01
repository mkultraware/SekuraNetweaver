using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Linq;

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

    // Stores original config per interface: servers + whether it was DHCP
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

        var allNics = GetAllGatewayInterfaces();
        if (!allNics.Any()) return;

        foreach (var iface in allNics)
        {
            if (providerName == "Original")
                RestoreOriginalDns(iface);
            else if (Providers.TryGetValue(providerName, out var servers))
                SetDnsServers(iface, servers);
        }

        CurrentProvider = providerName;
    }

    private void CacheAllOriginalDns()
    {
        foreach (var iface in GetAllGatewayInterfaces())
        {
            var (servers, isDhcp) = GetCurrentDnsConfig(iface);
            _originalDns[iface] = new DnsConfig(servers, isDhcp);
        }
    }

    private void RestoreOriginalDns(string iface)
    {
        if (!_originalDns.TryGetValue(iface, out var config)) return;

        if (config.IsDhcp)
        {
            // Restore to DHCP - requires setting source=dhcp, not source=static
            RunNetsh($"interface ip set dns name=\"{iface}\" source=dhcp");
        }
        else
        {
            SetDnsServers(iface, config.Servers);
        }
    }

    /// <summary>
    /// Parses netsh output to extract DNS servers and whether they're DHCP-assigned.
    /// netsh output format:
    ///   "    DNS servers configured through DHCP:  192.168.1.1"
    ///   "    Statically Configured DNS Servers:    8.8.8.8"
    ///   "                                          8.8.4.4"   (continuation)
    /// </summary>
    private (string[] servers, bool isDhcp) GetCurrentDnsConfig(string iface)
    {
        var output = RunNetshOutput($"interface ip show dns name=\"{iface}\"");
        var servers = new List<string>();
        bool isDhcp = false;
        bool capturing = false;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();

            if (trimmed.StartsWith("DNS servers configured through DHCP", StringComparison.OrdinalIgnoreCase))
            {
                isDhcp = true;
                capturing = true;
                var ip = ExtractIpFromConfigLine(trimmed);
                if (ip != null) servers.Add(ip);
                continue;
            }

            if (trimmed.StartsWith("Statically Configured DNS Servers", StringComparison.OrdinalIgnoreCase))
            {
                isDhcp = false;
                capturing = true;
                var ip = ExtractIpFromConfigLine(trimmed);
                if (ip != null) servers.Add(ip);
                continue;
            }

            // Continuation lines: pure IP addresses on their own
            if (capturing && IsValidIpAddress(trimmed))
            {
                servers.Add(trimmed);
                continue;
            }

            // Any other non-empty line ends the server block
            if (capturing && !string.IsNullOrWhiteSpace(trimmed))
                capturing = false;
        }

        return (servers.ToArray(), isDhcp);
    }

    private static string? ExtractIpFromConfigLine(string line)
    {
        // Lines look like: "DNS servers configured through DHCP:  192.168.1.1"
        var colonIdx = line.LastIndexOf(':');
        if (colonIdx < 0) return null;
        var candidate = line[(colonIdx + 1)..].Trim();
        return IsValidIpAddress(candidate) ? candidate : null;
    }

    private static bool IsValidIpAddress(string s)
    {
        return System.Net.IPAddress.TryParse(s, out _);
    }

    private void SetDnsServers(string iface, string[] servers)
    {
        if (servers.Length == 0) return;

        RunNetsh($"interface ip set dns name=\"{iface}\" source=static address={servers[0]}");

        for (int i = 1; i < servers.Length; i++)
            RunNetsh($"interface ip add dns name=\"{iface}\" {servers[i]} index={i + 1}");
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
        var iface = GetPrimaryInterface();
        if (iface == null) return "Unknown";

        var (servers, _) = GetCurrentDnsConfig(iface);
        foreach (var kvp in Providers)
        {
            if (kvp.Value.Intersect(servers).Any())
                return kvp.Key;
        }
        return "Custom/Original";
    }

    private static string? GetPrimaryInterface()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.GetIPProperties().GatewayAddresses.Count > 0)
            .Select(n => n.Name)
            .FirstOrDefault();
    }

    private static List<string> GetAllGatewayInterfaces()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.GetIPProperties().GatewayAddresses.Count > 0)
            .Select(n => n.Name)
            .ToList();
    }

    // The app manifest requests admin elevation (requiresAdministrator), so netsh
    // runs in the existing elevated context. No Verb = "runas" needed — that would
    // spawn a second UAC prompt on top of the one the user already accepted.
    private static void RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            var proc = Process.Start(psi);
            proc?.WaitForExit(5000);
        }
        catch { }
    }

    private static string RunNetshOutput(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(5000);
            return output;
        }
        catch { return string.Empty; }
    }
}
