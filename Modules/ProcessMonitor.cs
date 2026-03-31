using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SekuraNetweaver.Modules;

public class ProcessMonitor
{
    public event Action<string, string, string, bool, int, string>? OnSuspiciousProcess;

    private Thread? _thread;
    private bool _running;
    private readonly Dictionary<string, DateTime> _alerted = new();  
    private readonly ConcurrentDictionary<string, (string host, DateTime expiry)> _dnsCache = new();
    private DateTime _lastDnsCleanup = DateTime.MinValue;
    private readonly string _powershellPath = "powershell.exe";
    private volatile bool _enabled = true;
    public bool Enabled 
    { 
        get => _enabled; 
        set => _enabled = value; 
    }

    private static readonly string whitelistPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SekuraNetweaver", "user-whitelist.txt");
    private static readonly string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SekuraNetweaver", "alerts.log");

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
            watcher.Deleted += (s, e) => { _dynamicWhitelist.Clear(); };
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
        "msedge", "chrome", "firefox", "brave", "opera", "safari",
        "onedrive", "teams", "slack", "discord", "zoom", "skype", "whatsapp",
        
        // Gaming & Launchers (expanded)
        "steam", "steamwebhelper", "steamservice", "epicgameslauncher", "origin", "eacore", "eaconsole",
        "uplay", "ubicommunication", "battlenet", "agent", "RiotClientServices", "LeagueClientUx",
        "r5apex", "battleeye", "beservice", "easyanticheat", "ac_server", "rtss", "msi_afterburner",
        "obs64", "obs", "streamlabs obs", "xsplit", "eadesktop", "ealauncher",
        
        // Anti-Cheat & Game Services
        "vgk", "vgc", "beservice", "beserver", "ac_server", "easyanticheat", "battleye", 
        "kernel32", "winhttp", "wininet",
        
        // Dev & IDE
        "code", "msbuild", "dotnet", "devenv", "rider64", "visualstudio",
        "language_server_windows_x64", "language_server_windows_x86",
        
        // Assistant
        "antigravity",
        
        // VPN
        "protonvpn.wireguardservice", "protonvpn.client",
        
        // NVIDIA/AMD/Intel
        "nvcontainer", "nvdisplay.container", "nvcplui", "nvidia container", "nvtelemetry",
        "amftelemetry", "roaming", "igfxtray",
        
        // Windows services/UI
        "wuauclt", "MsMpEng", "conhost", "mpdefendercoreservice",
        "taskhostw", "searchui", "mobsynccmanager", "securityhealthservice",
        "OneDriveStandaloneUpdater", "GoogleUpdate", "searchhost", "runtimebroker", "sgrmbroker", "fontdrvhost",
        "powershell: UnknownScript"
    };

    private static readonly HashSet<string> SafeDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com",
        "google.com", "googleapis.com", "google-analytics.com", "1e100.net", "googleusercontent.com",
        "cloudflare.com", "akamai.net", "fastly.net",
        "github.com", "githubusercontent.com",
        "apple.com", "icloud.com",
        "dropbox.com", "spotify.com", "discord.com", "slack.com",
        "azure.com", "azure.net", "visualstudio.com", "msedge.net"
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

    private static HashSet<string> _dynamicSafeDomains = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string domainWhitelistPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "user-domains.txt");

    private static HashSet<string> _dynamicWhitelist = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> DynamicWhitelist => _dynamicWhitelist;

    private static void LoadDynamicWhitelist()
    {
        try
        {
            if (File.Exists(whitelistPath))
            {
                var newWhitelist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in File.ReadAllLines(whitelistPath))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                    {
                        newWhitelist.Add(trimmed);
                    }
                }
                _dynamicWhitelist = newWhitelist;
            }
        }
        catch { }
    }

    public static void AddToWhitelist(string processName, string ip = "")
    {
        _dynamicWhitelist.Add(processName);
        File.AppendAllLines(whitelistPath, new[] { processName });
        LogAlert($"WHITELISTED: {processName} {(string.IsNullOrEmpty(ip) ? "" : $"(IP: {ip})")}");
    }

    private static void LoadDynamicWhitelists()
    {
        LoadDynamicWhitelist();
        LoadDynamicSafeDomains();
    }

    private static void LoadDynamicSafeDomains()
    {
        try
        {
            if (File.Exists(domainWhitelistPath))
            {
                var newDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in File.ReadAllLines(domainWhitelistPath))
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                        newDomains.Add(trimmed);
                }
                _dynamicSafeDomains = newDomains;
            }
        }
        catch { }
    }

    public static void TrustDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return;
        _dynamicSafeDomains.Add(domain);
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
            
            // Extract Common Name (CN) or Organization (O)
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
                    string protocol = conn.protocol;

                    if (pid < 500 || pid == -1) continue;
                    if (IsPrivateIp(remoteIp)) continue;

                    var process = GetProcess(pid);
                    if (process == null) continue;

                    var name = process.ProcessName.ToLowerInvariant();
                    var fullPath = string.Empty;
                    try { fullPath = process.MainModule?.FileName; } catch { }

                    // Specific check for PowerShell scripts
                    if (name == "powershell" || name == "pwsh")
                    {
                        var scriptName = GetPowerShellScript(pid);
                        if (!string.IsNullOrEmpty(scriptName))
                        {
                            name = $"powershell: {scriptName}";
                        }
                    }

                    // Security: Check if process is running from suspicious location
                    bool isSuspiciousPath = !string.IsNullOrEmpty(fullPath) && (
                        fullPath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\AppData\\Local\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains("\\Users\\Public\\", StringComparison.OrdinalIgnoreCase) ||
                        fullPath.Contains(":\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase)
                    );

                    // Security: Reverse DNS Lookup with Cache
                    string hostName = GetHostName(remoteIp);
                    bool isSafeDomain = IsSafeDomain(hostName);
                    
                    // Security: Digital Signature Check
                    string publisher = GetPublisher(fullPath);
                    bool isTrustedPublisher = !string.IsNullOrEmpty(publisher) && TrustedPublishers.Any(p => publisher.Contains(p, StringComparison.OrdinalIgnoreCase));

                    // Skip internal traffic (local network, loopback)
                    if (IsPrivateIp(remoteIp)) continue;

                    // Only skip if path is clean
                    if (!isSuspiciousPath)
                    {
                        if (StaticWhitelist.Contains(name) || DynamicWhitelist.Contains(name)) continue;
                        if (isSafeDomain) continue;
                        if (isTrustedPublisher && (remotePort == 80 || remotePort == 443)) continue;
                    }

                    var key = $"{name}:{remoteIp}:{remotePort}:{protocol}";
                    if (_alerted.TryGetValue(key, out var lastAlert) &&
                        (DateTime.Now - lastAlert).TotalMinutes < 5) 
                        continue;

                    _alerted[key] = DateTime.Now;
                    var alertMsg = $"{protocol} {name} → {remoteIp}:{remotePort} {(string.IsNullOrEmpty(hostName) ? "" : $"({hostName})")}";
                    
                    if (isSuspiciousPath) alertMsg += " [SUSPICIOUS PATH]";
                    
                    LogAlert($"ALERT: {alertMsg}");
                    bool isUdp = protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase);
                    OnSuspiciousProcess?.Invoke(name, remoteIp, hostName, isUdp, remotePort, publisher);

                    // Log but do not terminate
                    LogAlert($"DETECTED: {name} ({pid}) - Suspicious {protocol} connection to {remoteIp}:{remotePort} ({hostName})");
                }

                // Periodic DNS cache cleanup
                if ((DateTime.Now - _lastDnsCleanup).TotalHours > 1)
                {
                    CleanupDnsCache();
                    _lastDnsCleanup = DateTime.Now;
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
            // Use a short timeout for DNS lookup to avoid blocking the monitor loop
            var host = Dns.GetHostEntry(ip).HostName;
            _dnsCache[ip] = (host, DateTime.Now.AddHours(1));
            return host;
        }
        catch
        {
            _dnsCache[ip] = (string.Empty, DateTime.Now.AddMinutes(10)); // Cache failure for a bit
            return string.Empty;
        }
    }

    private bool IsSafeDomain(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        
        bool isSafe = SafeDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        if (isSafe) return true;

        return _dynamicSafeDomains.Any(d => host.Equals(d, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    }

    private void CleanupDnsCache()
    {
        var now = DateTime.Now;
        var expiredKeys = _dnsCache.Where(kvp => kvp.Value.expiry < now).Select(kvp => kvp.Key).ToList();
        foreach (var key in expiredKeys)
            _dnsCache.TryRemove(key, out _);
    }

    private List<(int pid, string ip, int port, string protocol)> GetActiveConnections()
    {
        var results = new List<(int, string, int, string)>();

        try
        {
            // Use PowerShell to get detailed info (TCP and UDP)
            var script = "Get-NetTCPConnection -State Established | Select-Object OwningProcess, RemoteAddress, RemotePort; " +
                         "Get-NetUDPEndpoint | Select-Object OwningProcess, LocalAddress, LocalPort";
                         
            var psi = new ProcessStartInfo(_powershellPath, $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit();

            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains("OwningProcess") || line.Contains("-------")) continue;
                
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3) continue;

                if (!int.TryParse(parts[0], out var pid)) continue;
                var ip = parts[1];
                if (!int.TryParse(parts[2], out var port)) continue;

                // Simple heuristic to distinguish TCP/UDP output if piped together
                // In actual execution, we might want to run them separately or add a Marker
                string proto = "TCP"; 
                if (ip == "0.0.0.0" || ip == "::") proto = "UDP";

                results.Add((pid, ip, port, proto));
            }
        }
        catch { }

        return results;
    }

    private static Process? GetProcess(int pid)
    {
        if (pid <= 0) return null;
        try
        {
            return Process.GetProcessById(pid);
        }
        catch
        {
            return null;
        }
    }

    private string? GetPowerShellScript(int pid)
    {
        try
        {
            var psi = new ProcessStartInfo(_powershellPath, $"-NoProfile -ExecutionPolicy Bypass -Command \"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty CommandLine\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            var proc = Process.Start(psi);
            var output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit();

            // Looking for .ps1 or .psm1 in the command line
            if (output.Contains(".ps1", StringComparison.OrdinalIgnoreCase))
            {
                var parts = output.Split(new[] { ' ', '\"', '\'' }, StringSplitOptions.RemoveEmptyEntries);
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

