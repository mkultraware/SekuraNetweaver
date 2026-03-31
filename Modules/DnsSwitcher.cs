using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Linq;
using Microsoft.Win32;

namespace SekuraNetweaver.Modules;

public class DnsSwitcher
{
    public static readonly Dictionary<string, string[]> Providers = new Dictionary<string, string[]>
    {
        { "Cloudflare", new string[] { "1.1.1.1", "1.0.0.1" } },
        { "Quad9", new string[] { "9.9.9.9", "149.112.112.112" } },
        { "Google", new string[] { "8.8.8.8", "8.8.4.4" } },
        { "Original", new string[] { } },
    };

    private readonly Dictionary<string, string[]> _originalDns = new();
    private readonly Dictionary<string, string[]> _currentDns = new();
    public string CurrentProvider { get; private set; } = "Unknown";

    public DnsSwitcher()
    {
        CacheAllOriginalDns();
        CurrentProvider = DetectCurrentProvider();
    }

    public void SwitchTo(string providerName)
    {
        if (!Providers.ContainsKey(providerName))
            return;

        var allNics = GetAllGatewayInterfaces();
        if (!allNics.Any()) return;

        foreach (var iface in allNics)
        {
            if (providerName == "Original")
            {
                RestoreOriginalDns(iface);
            }
            else if (Providers.TryGetValue(providerName, out var servers))
            {
                SetDnsServers(iface, servers);
            }
        }

        CurrentProvider = providerName;
    }

    private void CacheAllOriginalDns()
    {
        var allNics = GetAllGatewayInterfaces();
        foreach (var iface in allNics)
        {
            var dnsServers = GetCurrentDnsServers(iface);
            _originalDns[iface] = dnsServers;
            _currentDns[iface] = dnsServers;
        }
    }

    private void RestoreOriginalDns(string iface)
    {
        if (_originalDns.TryGetValue(iface, out var original))
        {
            SetDnsServers(iface, original);
        }
    }

    private string[] GetCurrentDnsServers(string iface)
    {
        var result = RunNetshOutput($"interface ip show dns name=\"{iface}\"");
        var dnsServers = new List<string>();
        var lines = result.Split('\n');
        foreach (var line in lines)
        {
            if (line.Contains("Statically Configured DNS Servers") || line.Contains("DNS servers configured through DHCP"))
            {
                var servers = line.Split(',').Select(s => s.Trim().Split(':')[0].Trim()).Where(s => !string.IsNullOrEmpty(s)).ToArray();
                dnsServers.AddRange(servers);
            }
        }
        return dnsServers.ToArray();
    }

    private void SetDnsServers(string iface, string[] servers)
    {
        RunNetsh($"interface ip set dns name=\"{iface}\" source=static address={servers.FirstOrDefault() ?? ""}");
        
        for (int i = 1; i < servers.Length; i++)
        {
            RunNetsh($"interface ip add dns name=\"{iface}\" {servers[i]} index={i + 1}");
        }
        
        _currentDns[iface] = servers;
    }

    public bool IsDoHEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator\DoHServers");
            return key != null;
        }
        catch
        {
            return false;
        }
    }

    private string DetectCurrentProvider()
    {
        var iface = GetPrimaryInterface();
        if (iface == null) return "Unknown";

        var dns = GetCurrentDnsServers(iface);
        foreach (var kvp in Providers)
        {
            if (kvp.Value.Intersect(dns).Any())
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

    private static void RunNetsh(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            Verb = "runas",
            UseShellExecute = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        Process.Start(psi)?.WaitForExit(5000);
    }

    private static string RunNetshOutput(string args)
    {
        var psi = new ProcessStartInfo("netsh", args)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        var proc = Process.Start(psi);
        return proc?.StandardOutput.ReadToEnd() ?? "";
    }
}

