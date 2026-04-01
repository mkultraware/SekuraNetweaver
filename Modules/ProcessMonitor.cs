using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace SekuraNetweaver.Modules;

public class ProcessMonitor
{
    public event Action<string, string, string, bool, int, string>? OnSuspiciousProcess;

    private Thread? _thread;
    private bool _running;
    // Only touched from monitor thread - no lock needed
    private readonly Dictionary<string, DateTime> _alerted = new();
    private DateTime _lastAlertedCleanup = DateTime.MinValue;
    private readonly ConcurrentDictionary<string, (string host, DateTime expiry)> _dnsCache = new();
    private DateTime _lastDnsCleanup = DateTime.MinValue;
    private readonly string _powershellPath = "powershell.exe";
    private volatile bool _enabled = true;

    public bool Enabled
    {
        get => _enabled;
        set => _enabled = value;
    }

    private static readonly string whitelistPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SekuraNetweaver", "user-whitelist.txt");

    private static readonly string logPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SekuraNetweaver", "alerts.log");

    static ProcessMonitor()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(whitelistPath) ?? "");
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? "");
        LoadDynamicWhitelists();
        SetupWatcher();
    }

    private static void SetupWatcher()
    {
        try
        {
            var directory = Path.GetDirectoryName(whitelistPath);
            if (directory == null) return;

            var watcher = new FileSystemWatcher(directory)
            {
                Filter = Path.GetFileName(whitelistPath),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size
            };
            watcher.Changed += (s, e) => LoadDynamicWhitelists();
            watcher.Created += (s, e) => LoadDynamicWhitelists();
            watcher.Deleted += (s, e) => { _dynamicWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase); };
            watcher.EnableRaisingEvents = true;
        }
        catch { }
    }

    private static readonly HashSet<string> StaticWhitelist = new(StringComparer.OrdinalIgnoreCase)
    {
        // Core Windows
        "svchost", "lsass", "wininit", "services", "explorer",
        "dwm", "csrss", "smss", "winlogon", "spoolsv",

        // Browsers & Communication
        "msedge", "chrome", "firefox", "brave", "opera",
        "onedrive", "teams", "slack", "discord", "zoom", "skype", "whatsapp",

        // Gaming & Launchers
        "steam", "steamwebhelper", "steamservice", "epicgameslauncher", "origin", "eacore",
        "uplay", "ubicommunication", "battlenet", "agent", "riotclientservices", "leagueclientux",
        "r5apex", "battleeye", "beservice", "easyanticheat", "rtss", "msi_afterburner",
        "obs64", "obs", "xsplit", "eadesktop", "ealauncher",

        // Anti-Cheat & Game Services
        "vgk", "vgc",

        // Dev & IDE
        "code", "msbuild", "dotnet", "devenv", "rider64",

        // VPN
        "protonvpn.wireguardservice", "protonvpn.client",

        // NVIDIA/AMD/Intel
        "nvcontainer", "nvdisplay.container", "nvcplui", "nvtelemetry",
        "amftelemetry", "igfxtray",

        // Windows services & Core Utilities
        "wuauclt", "msmpeng", "conhost", "mpdefendercoreservice",
        "taskhostw", "searchui", "securityhealthservice",
        "onedrivestantaloneupdater", "googleupdate", "searchhost",
        "runtimebroker", "sgrmbroker", "fontdrvhost", "systemsettings",
        "compattelrunner", "ctfmon", "smartscreen", "browser_broker",

        // Known good PS scripts
        "powershell: unknownscript"
    };

    private static readonly HashSet<string> SafeDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com",
        "google.com", "googleapis.com", "1e100.net", "googleusercontent.com",
        "cloudflare.com", "akamai.net", "fastly.net", "akamaitechnologies.com",
        "github.com", "githubusercontent.com",
        "apple.com", "icloud.com",
        "dropbox.com", "spotify.com", "discord.com", "slack.com",
        "azure.com", "azure.net", "visualstudio.com", "msedge.net",
        "ea.com", "origin.com", "ubisoft.com", "ubi.com",
        "awsglobalaccelerator.com", "microsoftonline.com"
    };

    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation",
        "Google LLC",
        "Valve Corp.",
        "Electronic Arts, Inc.",
        "NVIDIA Corporation",
        "Advanced Micro Devices, Inc.",
        "Proton AG",
        "Valve",
        "Apple Inc.",
        "Intel Corporation"
    };

    // volatile ensures the reference replacement from FileSystemWatcher thread is immediately visible
    // to the monitor thread. The HashSet itself is replaced wholesale, never mutated in place.
    private static volatile HashSet<string> _dynamicWhitelist = new(StringComparer.OrdinalIgnoreCase);
    private static volatile HashSet<string> _dynamicSafeDomains = new(StringComparer.OrdinalIgnoreCase);

    private static readonly string domainWhitelistPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "user-domains.txt");

    public static HashSet<string> DynamicWhitelist => _dynamicWhitelist;

    private static void LoadDynamicWhitelists()
    {
        LoadDynamicWhitelist();
        LoadDynamicSafeDomains();
    }

    private static void LoadDynamicWhitelist()
    {
        try
        {
            if (!File.Exists(whitelistPath)) return;

            var newWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadAllLines(whitelistPath))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                    newWhitelist.Add(trimmed);
            }
            _dynamicWhitelist = newWhitelist;
        }
        catch { }
    }

    private static void LoadDynamicSafeDomains()
    {
        try
        {
            if (!File.Exists(domainWhitelistPath)) return;

            var newDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadAllLines(domainWhitelistPath))
            {
                var trimmed = line.Trim();
                if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                    newDomains.Add(trimmed);
            }
            _dynamicSafeDomains = newDomains;
        }
        catch { }
    }

    public static void AddToWhitelist(string processName, string ip = "")
    {
        var current = _dynamicWhitelist;
        var updated = new HashSet<string>(current, StringComparer.OrdinalIgnoreCase) { processName };
        _dynamicWhitelist = updated;
        File.AppendAllLines(whitelistPath, new[] { processName });
        LogAlert($"WHITELISTED: {processName} {(string.IsNullOrEmpty(ip) ? "" : $"(IP: {ip})")}");
    }

    public static void TrustDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return;
        var current = _dynamicSafeDomains;
        var updated = new HashSet<string>(current, StringComparer.OrdinalIgnoreCase) { domain };
        _dynamicSafeDomains = updated;
        File.AppendAllLines(domainWhitelistPath, new[] { domain });
        LogAlert($"TRUSTED DOMAIN: {domain}");
    }

    private string GetPublisher(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return string.Empty;
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(path);
            var subject = cert.Subject;
            var parts = subject.Split(',').Select(p => p.Trim());
            var cn = parts.FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?.Substring(3);
            var o = parts.FirstOrDefault(p => p.StartsWith("O=", StringComparison.OrdinalIgnoreCase))?.Substring(2);
            return cn ?? o ?? subject;
        }
        catch
        {
            return string.Empty;
        }
    }

    // --- P/Invoke: GetExtendedTcpTable ---
    // Replaces the PowerShell Get-NetTCPConnection approach.
    // No process spawn overhead, no 5-second latency tax, no EDR false positives.

    private enum TcpTableClass
    {
        TcpTableOwnerPidConnections = 4 // Established connections with owning PID
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, TcpTableClass tblClass, uint reserved);

    private static List<(int pid, string ip, int port)> GetActiveConnections()
    {
        var results = new List<(int, string, int)>();

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2 /*AF_INET*/, TcpTableClass.TcpTableOwnerPidConnections, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref bufferSize, false, 2, TcpTableClass.TcpTableOwnerPidConnections, 0);
            if (ret != 0) return results;

            int numEntries = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr rowPtr = buffer + 4; // skip past dwNumEntries

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr + i * rowSize);

                var remoteIp = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();

                // Port is stored in network byte order in the low 16 bits of the DWORD
                ushort rawPort = (ushort)(row.dwRemotePort & 0xFFFF);
                int remotePort = ((rawPort & 0xFF) << 8) | (rawPort >> 8);

                results.Add(((int)row.dwOwningPid, remoteIp, remotePort));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return results;
    }

    private static readonly List<IPNetwork2> PrivateRanges = new()
    {
        IPNetwork2.Parse("10.0.0.0/8"),
        IPNetwork2.Parse("172.16.0.0/12"),
        IPNetwork2.Parse("192.168.0.0/16"),
        IPNetwork2.Parse("127.0.0.0/8"),
        IPNetwork2.Parse("169.254.0.0/16"),
        IPNetwork2.Parse("::1/128"),
    };

    public void Start()
    {
        _running = true;
        _thread = new Thread(Monitor) { IsBackground = true, Name = "ProcessMonitor" };
        _thread.Start();
    }

    public void Stop()
    {
        _running = false;
    }

    private void Monitor()
    {
        while (_running)
        {
            if (!_enabled)
            {
                Thread.Sleep(1000);
                continue;
            }

            try
            {
                var connections = GetActiveConnections();

                foreach (var conn in connections)
                {
                    int pid = conn.pid;
                    string remoteIp = conn.ip;
                    int remotePort = conn.port;

                    if (pid < 500) continue;
                    if (IsPrivateIp(remoteIp)) continue;

                    var process = GetProcess(pid);
                    if (process == null) continue;

                    var name = process.ProcessName.ToLowerInvariant();
                    string fullPath = string.Empty;
                    try { fullPath = process.MainModule?.FileName ?? string.Empty; } catch { }

                    // Check path before doing any expensive operations
                    bool isSuspiciousPath = !string.IsNullOrEmpty(fullPath) && (
                        fullPath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\Users\\Public\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains(":\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase)
                    );

                    if (!isSuspiciousPath)
                    {
                        if (StaticWhitelist.Contains(name) || _dynamicWhitelist.Contains(name)) continue;
                    }

                    // Trusted Paths: System-installed or Developer Extensions
                    string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    bool isTrustedPath = !string.IsNullOrEmpty(fullPath) && (
                        fullPath.StartsWith("C:\\Program Files\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.StartsWith("C:\\Program Files (x86)\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains(".vscode\\extensions", StringComparison.OrdinalIgnoreCase)
                    );

                    if (isTrustedPath)
                    {
                        // SILENT TRUST: Admin or Dev installed software is implicitly safe.
                        LogAlert($"TRUSTED [SAFE PATH]: {name} → {remoteIp}:{remotePort}");
                        continue;
                    }

                    // Reverse DNS with timeout - only done if process isn't already trusted
                    string hostName = GetHostName(remoteIp);
                    bool isSafeDomain = IsSafeDomain(hostName);

                    if (!isSuspiciousPath && isSafeDomain) continue;

                    // Signature Check - The core of the "Trust-All-Signed" model.
                    // Reputable software (Mozilla, Google, Steam, etc.) is now implicitly trusted.
                    string publisher = GetPublisher(fullPath);
                    bool isSigned = !string.IsNullOrEmpty(publisher);

                    if (isSigned)
                    {
                        if (!isSuspiciousPath)
                        {
                            // SILENT TRUST: Don't notify, but log it for forensics.
                            LogAlert($"TRUSTED: {name} (Signed by: {publisher}) → {remoteIp}:{remotePort}");
                            continue;
                        }
                        else
                        {
                            // SUSPICIOUS PATH ALERT: Even if signed, alert if running from Temp/Public.
                            LogAlert($"ALERT [SUSPICIOUS PATH (SIGNED)]: {name} (Signed by: {publisher}) → {remoteIp}:{remotePort}");
                        }
                    }
                    else
                    {
                        // UNSIGNED ALERT: No signature found. Always treat as suspicious.
                        LogAlert($"ALERT [UNSIGNED]: {name} → {remoteIp}:{remotePort}");
                    }

                    // PS script auditing - only when we're already going to alert
                    if (name == "powershell" || name == "pwsh")
                    {
                        var scriptName = GetPowerShellScript(pid);
                        if (!string.IsNullOrEmpty(scriptName))
                            name = $"powershell: {scriptName}";
                    }

                    var alertKey = $"{name}:{remoteIp}:{remotePort}";
                    if (_alerted.TryGetValue(alertKey, out var lastAlert) &&
                        (DateTime.Now - lastAlert).TotalMinutes < 5)
                        continue;

                    _alerted[alertKey] = DateTime.Now;

                    var alertMsg = $"TCP {name} → {remoteIp}:{remotePort} {(string.IsNullOrEmpty(hostName) ? "" : $"({hostName})")}";
                    if (isSuspiciousPath) alertMsg += " [SUSPICIOUS PATH]";
                    LogAlert($"ALERT: {alertMsg}");

                    OnSuspiciousProcess?.Invoke(name, remoteIp, hostName, false, remotePort, publisher);
                }

                // Periodic cleanups
                if ((DateTime.Now - _lastDnsCleanup).TotalHours > 1)
                {
                    CleanupDnsCache();
                    _lastDnsCleanup = DateTime.Now;
                }

                if ((DateTime.Now - _lastAlertedCleanup).TotalHours > 1)
                {
                    var cutoff = DateTime.Now.AddHours(-1);
                    foreach (var key in _alerted.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList())
                        _alerted.Remove(key);
                    _lastAlertedCleanup = DateTime.Now;
                }
            }
            catch (Exception ex)
            {
                LogAlert($"Monitor error: {ex.Message}");
            }

            Thread.Sleep(5000);
        }
    }

    private string GetHostName(string ip)
    {
        if (_dnsCache.TryGetValue(ip, out var cached) && cached.expiry > DateTime.Now)
            return cached.host;

        try
        {
            // 2-second timeout - blocking Dns.GetHostEntry can stall for much longer
            var task = Task.Run(() => Dns.GetHostEntry(ip).HostName);
            if (task.Wait(TimeSpan.FromSeconds(2)))
            {
                var host = task.Result;
                _dnsCache[ip] = (host, DateTime.Now.AddHours(1));
                return host;
            }
        }
        catch { }

        _dnsCache[ip] = (string.Empty, DateTime.Now.AddMinutes(10));
        return string.Empty;
    }

    private static bool IsSafeDomain(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;

        if (SafeDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                  host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
            return true;

        return _dynamicSafeDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                             host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    }

    private void CleanupDnsCache()
    {
        var now = DateTime.Now;
        foreach (var key in _dnsCache.Where(kvp => kvp.Value.expiry < now).Select(kvp => kvp.Key).ToList())
            _dnsCache.TryRemove(key, out _);
    }

    private static Process? GetProcess(int pid)
    {
        if (pid <= 0) return null;
        try { return Process.GetProcessById(pid); }
        catch { return null; }
    }

    private string? GetPowerShellScript(int pid)
    {
        try
        {
            var psi = new ProcessStartInfo(_powershellPath,
                $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty CommandLine\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(3000);

            if (output.Contains(".ps1", StringComparison.OrdinalIgnoreCase))
            {
                var parts = output.Split(new[] { ' ', '"', '\'' }, StringSplitOptions.RemoveEmptyEntries);
                return parts.FirstOrDefault(p => p.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)) ?? "UnknownScript";
            }
        }
        catch { }
        return null;
    }

    private static bool IsPrivateIp(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return true;
        if (IPAddress.IsLoopback(ip)) return true;
        foreach (var range in PrivateRanges)
        {
            if (range.Contains(ip)) return true;
        }
        return false;
    }

    private static void LogAlert(string message)
    {
        try
        {
            var logLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
            File.AppendAllText(logPath, logLine);
            Debug.WriteLine(logLine);
        }
        catch { }
    }
}

public class IPNetwork2
{
    private readonly IPAddress _network;
    private readonly int _prefix;

    private IPNetwork2(IPAddress network, int prefix)
    {
        _network = network;
        _prefix = prefix;
    }

    public static IPNetwork2 Parse(string cidr)
    {
        var parts = cidr.Split('/');
        var address = IPAddress.Parse(parts[0]);
        var prefix = int.Parse(parts[1]);
        return new IPNetwork2(address, prefix);
    }

    public bool Contains(IPAddress address)
    {
        try
        {
            var netBytes = _network.GetAddressBytes();
            var addrBytes = address.GetAddressBytes();
            if (netBytes.Length != addrBytes.Length) return false;

            var fullBytes = _prefix / 8;
            var remaining = _prefix % 8;

            for (int i = 0; i < fullBytes; i++)
                if (netBytes[i] != addrBytes[i]) return false;

            if (remaining > 0)
            {
                var mask = (byte)(0xFF << (8 - remaining));
                if ((netBytes[fullBytes] & mask) != (addrBytes[fullBytes] & mask)) return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }
}
