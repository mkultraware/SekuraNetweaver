using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
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
    private readonly ConcurrentDictionary<string, DateTime> _alerted = new();
    private DateTime _lastAlertedCleanup = DateTime.MinValue;
    private readonly ConcurrentDictionary<string, (string host, DateTime expiry)> _dnsCache = new();
    private DateTime _lastDnsCleanup = DateTime.MinValue;
    private DateTime _lastModuleCacheCleanup = DateTime.MinValue;

    // Cache MainModule path by PID — avoids repeated Win32Exception on protected/PPL
    // processes and keeps the hot path fast.
    private readonly ConcurrentDictionary<int, (string path, DateTime expiry)> _moduleCache = new();

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

        // Anti-Cheat
        "vgk", "vgc",

        // Dev & IDE
        "code", "dotnet", "devenv", "rider64",

        // VPN
        "protonvpn.wireguardservice", "protonvpn.client",

        // NVIDIA/AMD/Intel
        "nvcontainer", "nvdisplay.container", "nvcplui", "nvtelemetry", "igfxtray",

        // Windows services
        "wuauclt", "msmpeng", "conhost", "mpdefendercoreservice",
        "taskhostw", "searchui", "securityhealthservice",
        "googleupdate", "searchhost", "runtimebroker", "sgrmbroker",
        "fontdrvhost", "systemsettings", "compattelrunner", "ctfmon",
        "smartscreen", "browser_broker",

        "powershell: unknownscript"
    };

    // LOLBins: signed or otherwise trusted binaries that are routinely abused for
    // payload delivery, code execution, and C2. These are NEVER trusted by publisher
    // alone — they skip the isTrustedPublisher check and always go through the full
    // alert pipeline. Note: msbuild and wmic are intentionally NOT in StaticWhitelist.
    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "certutil",          // download + decode base64 payloads
        "mshta",             // execute HTA / VBScript
        "wscript",           // execute .vbs / .js
        "cscript",           // console variant of wscript
        "regsvr32",          // AppLocker bypass via COM scriptlet (squiblydoo)
        "installutil",       // AppLocker bypass via .NET assembly
        "regasm",            // .NET COM registration abuse
        "regsvcs",           // same as regasm
        "msbuild",           // inline task execution for arbitrary .NET code
        "odbcconf",          // DLL registration abuse via /a {REGSVR}
        "hh",                // HTML Help — loads arbitrary CHM / JS
        "forfiles",          // arbitrary command via /c
        "pcalua",            // Program Compatibility Assistant bypass
        "bitsadmin",         // download arbitrary files
        "desktopimgdownldr", // download files to disk
        "esentutl",          // copy locked files for exfil
        "expand",            // expand cabinet from arbitrary paths
        "extrac32",          // same
        "mavinject",         // inject DLLs into running processes (Microsoft-signed)
        "msiexec",           // install arbitrary MSI payloads
        "presentationhost",  // execute XAML browser apps
        "replace",           // overwrite system files
        "wmic",              // execute arbitrary processes / scripts
        "xwizard",           // load arbitrary DLLs via COM
        "ieexec",            // download and execute from URL
        "makecab",           // archive exfil
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

    // volatile: FileSystemWatcher callback (thread pool) replaces the reference wholesale.
    // Monitor thread reads it. No lock needed — the set is never mutated in place.
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
            var next = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadAllLines(whitelistPath))
            {
                var t = line.Trim();
                if (!string.IsNullOrEmpty(t) && !t.StartsWith("#"))
                    next.Add(t);
            }
            _dynamicWhitelist = next;
        }
        catch { }
    }

    private static void LoadDynamicSafeDomains()
    {
        try
        {
            if (!File.Exists(domainWhitelistPath)) return;
            var next = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in File.ReadAllLines(domainWhitelistPath))
            {
                var t = line.Trim();
                if (!string.IsNullOrEmpty(t) && !t.StartsWith("#"))
                    next.Add(t);
            }
            _dynamicSafeDomains = next;
        }
        catch { }
    }

    public static void AddToWhitelist(string processName)
    {
        var updated = new HashSet<string>(_dynamicWhitelist, StringComparer.OrdinalIgnoreCase) { processName };
        _dynamicWhitelist = updated;
        File.AppendAllLines(whitelistPath, new[] { processName });
    }

    public static void TrustDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return;
        var updated = new HashSet<string>(_dynamicSafeDomains, StringComparer.OrdinalIgnoreCase) { domain };
        _dynamicSafeDomains = updated;
        File.AppendAllLines(domainWhitelistPath, new[] { domain });
    }

    private string GetCachedModulePath(int pid)
    {
        var now = DateTime.Now;
        if (_moduleCache.TryGetValue(pid, out var cached) && cached.expiry > now)
            return cached.path;

        string path = string.Empty;
        try { path = Process.GetProcessById(pid).MainModule?.FileName ?? string.Empty; }
        catch { }

        _moduleCache[pid] = (path, now.AddSeconds(60));
        return path;
    }

    private string GetPublisher(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return string.Empty;
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(path);
            var parts = cert.Subject.Split(',').Select(p => p.Trim());
            var cn = parts.FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?.Substring(3);
            var o  = parts.FirstOrDefault(p => p.StartsWith("O=",  StringComparison.OrdinalIgnoreCase))?.Substring(2);
            return cn ?? o ?? cert.Subject;
        }
        catch { return string.Empty; }
    }

    // --- P/Invoke: GetExtendedTcpTable ---

    private enum TcpTableClass { TcpTableOwnerPidConnections = 4 }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, TcpTableClass tblClass, uint reserved);

    private static List<(int pid, string ip, int port)> GetActiveConnections()
    {
        var results = new List<(int, string, int)>();
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, 2, TcpTableClass.TcpTableOwnerPidConnections, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, false, 2, TcpTableClass.TcpTableOwnerPidConnections, 0) != 0)
                return results;

            int numEntries = Marshal.ReadInt32(buffer);
            int rowSize    = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr rowPtr  = buffer + 4;

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr + i * rowSize);
                var ip = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                ushort raw = (ushort)(row.dwRemotePort & 0xFFFF);
                int port = ((raw & 0xFF) << 8) | (raw >> 8);
                results.Add(((int)row.dwOwningPid, ip, port));
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
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

    public void Stop() => _running = false;

    private void Monitor()
    {
        while (_running)
        {
            if (!_enabled) { Thread.Sleep(1000); continue; }

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
                    bool isLolBin = LolBins.Contains(name);
                    string fullPath = GetCachedModulePath(pid);

                    bool isSuspiciousPath = !string.IsNullOrEmpty(fullPath) && (
                        fullPath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\Users\\Public\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains(":\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase)
                    );

                    // PS script auditing — move before trust checks for better matching
                    if (name is "powershell" or "pwsh")
                    {
                        var scriptName = GetPowerShellScript(pid);
                        if (!string.IsNullOrEmpty(scriptName))
                            name = $"powershell: {scriptName}";
                    }

                    // Trust pipeline — skip if in whitelists or has trusted publisher
                    if (StaticWhitelist.Contains(name) || _dynamicWhitelist.Contains(name)) continue;

                    string publisher = GetPublisher(fullPath);
                    bool trustedPub = !string.IsNullOrEmpty(publisher) &&
                        TrustedPublishers.Any(p => publisher.Contains(p, StringComparison.OrdinalIgnoreCase));

                    bool isAuditOnly = false;
                    if (trustedPub && !isSuspiciousPath)
                    {
                        if (isLolBin)
                        {
                            isAuditOnly = true; // Log to file, but do not notify (BalloonTip)
                        }
                        else
                        {
                            continue; // Fully trusted non-lolbin in clean path
                        }
                    }

                    // PTR lookup — display context only, NOT a trust gate.
                    string hostName = GetHostName(remoteIp);

                    // Domain/IP whitelist check — user-trusted destinations are skipped silently.
                    if (_dynamicSafeDomains.Contains(remoteIp) ||
                        (!string.IsNullOrEmpty(hostName) && _dynamicSafeDomains.Contains(hostName)))
                        continue;

                    // Deduplication: same process+IP+port suppressed for 5 minutes.
                    // This covers ALL connections reaching this point — trusted or not —
                    // so persistent connections don't spam the log.
                    var alertKey = $"{name}:{remoteIp}:{remotePort}";
                    if (_alerted.TryGetValue(alertKey, out var lastAlert) &&
                        (DateTime.Now - lastAlert).TotalMinutes < 5)
                        continue;

                    _alerted[alertKey] = DateTime.Now;

                    var tags = new System.Text.StringBuilder();
                    if (isSuspiciousPath) tags.Append(" [SUSPICIOUS PATH]");
                    if (isLolBin)         tags.Append(" [LOLBIN]");

                    if (isAuditOnly)
                    {
                        LogAlert($"[AUDIT] TCP {name} → {remoteIp}:{remotePort}" +
                                 $"{(string.IsNullOrEmpty(hostName) ? "" : $" ({hostName})")}" +
                                 tags + " (Signed LOLBin)");
                    }
                    else
                    {
                        LogAlert($"ALERT: TCP {name} → {remoteIp}:{remotePort}" +
                                 $"{(string.IsNullOrEmpty(hostName) ? "" : $" ({hostName})")}" +
                                 tags);

                        OnSuspiciousProcess?.Invoke(name, remoteIp, hostName, false, remotePort, publisher);
                    }
                }

                var now = DateTime.Now;

                if ((now - _lastDnsCleanup).TotalHours > 1)
                {
                    CleanupDnsCache();
                    _lastDnsCleanup = now;
                }

                if ((now - _lastAlertedCleanup).TotalHours > 1)
                {
                    var cutoff = now.AddHours(-1);
                    foreach (var k in _alerted.Where(kvp => kvp.Value < cutoff).Select(kvp => kvp.Key).ToList())
                        _alerted.TryRemove(k, out _);
                    _lastAlertedCleanup = now;
                }

                if ((now - _lastModuleCacheCleanup).TotalMinutes > 10)
                {
                    foreach (var k in _moduleCache.Where(kvp => kvp.Value.expiry < now).Select(kvp => kvp.Key).ToList())
                        _moduleCache.TryRemove(k, out _);
                    _lastModuleCacheCleanup = now;
                }
            }
            catch (Exception ex) { LogAlert($"Monitor error: {ex.Message}"); }

            Thread.Sleep(5000);
        }
    }

    private string GetHostName(string ip)
    {
        if (_dnsCache.TryGetValue(ip, out var cached) && cached.expiry > DateTime.Now)
            return cached.host;

        try
        {
            var task = Task.Run(() => Dns.GetHostEntry(ip).HostName);
            if (task.Wait(TimeSpan.FromSeconds(2)))
            {
                _dnsCache[ip] = (task.Result, DateTime.Now.AddHours(1));
                return task.Result;
            }
        }
        catch { }

        _dnsCache[ip] = (string.Empty, DateTime.Now.AddMinutes(10));
        return string.Empty;
    }

    private void CleanupDnsCache()
    {
        var now = DateTime.Now;
        foreach (var k in _dnsCache.Where(kvp => kvp.Value.expiry < now).Select(kvp => kvp.Key).ToList())
            _dnsCache.TryRemove(k, out _);
    }

    private static Process? GetProcess(int pid)
    {
        if (pid <= 0) return null;
        try { return Process.GetProcessById(pid); }
        catch { return null; }
    }

    private static string? GetPowerShellScript(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var output = obj["CommandLine"]?.ToString() ?? "";
                if (output.Contains(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = output.Split(new[] { ' ', '"', '\'' }, StringSplitOptions.RemoveEmptyEntries);
                    return parts.FirstOrDefault(p => p.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)) ?? "UnknownScript";
                }
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
            if (range.Contains(ip)) return true;
        return false;
    }

    private static void LogAlert(string message)
    {
        try
        {
            File.AppendAllText(logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}");
            Debug.WriteLine(message);
        }
        catch { }
    }
}

public class IPNetwork2
{
    private readonly IPAddress _network;
    private readonly int _prefix;

    private IPNetwork2(IPAddress network, int prefix) { _network = network; _prefix = prefix; }

    public static IPNetwork2 Parse(string cidr)
    {
        var parts = cidr.Split('/');
        return new IPNetwork2(IPAddress.Parse(parts[0]), int.Parse(parts[1]));
    }

    public bool Contains(IPAddress address)
    {
        try
        {
            var net  = _network.GetAddressBytes();
            var addr = address.GetAddressBytes();
            if (net.Length != addr.Length) return false;

            int full = _prefix / 8, rem = _prefix % 8;
            for (int i = 0; i < full; i++)
                if (net[i] != addr[i]) return false;

            if (rem > 0)
            {
                var mask = (byte)(0xFF << (8 - rem));
                if ((net[full] & mask) != (addr[full] & mask)) return false;
            }
            return true;
        }
        catch { return false; }
    }
}
