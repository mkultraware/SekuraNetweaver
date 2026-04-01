using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using SekuraNetweaver.Modules;
using SekuraNetweaver.UI;

namespace SekuraNetweaver;

public class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly DnsSwitcher _dns;
    private readonly WifiAuditor _wifi;
    private readonly ProcessMonitor _process;
    private readonly System.Threading.SynchronizationContext? _syncContext;

    private string? _lastSuspiciousProcess;

    public TrayApp()
    {
        _dns     = new DnsSwitcher();
        _wifi    = new WifiAuditor();
        _process = new ProcessMonitor();

        _tray = new NotifyIcon
        {
            Icon    = new System.Drawing.Icon(GetIconPath()),
            Visible = true,
            Text    = "Sekura Netweaver"
        };

        _tray.ContextMenuStrip = BuildMenu();
        _syncContext = System.Threading.SynchronizationContext.Current;
        _process.OnSuspiciousProcess += OnSuspiciousProcess;
        _process.Start();
    }

    private string GetIconPath()
    {
        var candidates = new[]
        {
            System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "icon.ico"),
            System.IO.Path.Combine(AppContext.BaseDirectory, "icon.ico"),
            System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "icon.ico"),
        };
        return candidates.FirstOrDefault(System.IO.File.Exists) ?? "";
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();

        // --- WiFi status ---
        var wifiStatus = _wifi.GetStatus();
        var wifiItem   = new ToolStripMenuItem($"WiFi: {wifiStatus}") { Enabled = false };
        menu.Items.Add(wifiItem);
        menu.Items.Add(new ToolStripSeparator());

        // --- DNS ---
        var dnsMenu = new ToolStripMenuItem("DNS");
        foreach (var provider in DnsSwitcher.Providers)
        {
            var item     = new ToolStripMenuItem(provider.Key);
            item.Click  += (s, e) => SwitchDns(provider.Key);
            item.Checked = _dns.CurrentProvider == provider.Key;
            dnsMenu.DropDownItems.Add(item);
        }
        menu.Items.Add(dnsMenu);
        menu.Items.Add(new ToolStripSeparator());

        // --- Process Monitor Toggle ---
        var monitorLabel = _process.Enabled ? "Process Monitor: On" : "Process Monitor: Off";
        var monitorToggle = new ToolStripMenuItem(monitorLabel) { Checked = _process.Enabled };
        monitorToggle.Click += (s, e) =>
        {
            _process.Enabled = !_process.Enabled;
            monitorToggle.Text = _process.Enabled ? "Process Monitor: On" : "Process Monitor: Off";
            monitorToggle.Checked = _process.Enabled;
        };
        menu.Items.Add(monitorToggle);
        menu.Items.Add(new ToolStripSeparator());

        // --- Whitelist ---
        if (!string.IsNullOrEmpty(_lastSuspiciousProcess))
        {
            var quickWhitelist = new ToolStripMenuItem($"Whitelist {_lastSuspiciousProcess}");
            quickWhitelist.Click += (s, e) => 
            {
                ProcessMonitor.AddToWhitelist(_lastSuspiciousProcess);
                _lastSuspiciousProcess = null;
                _tray.ContextMenuStrip = BuildMenu(); // Refresh
            };
            menu.Items.Add(quickWhitelist);
        }

        var whitelistItem = new ToolStripMenuItem("Edit Whitelist");
        whitelistItem.Click += (s, e) => OpenWhitelist();
        menu.Items.Add(whitelistItem);

        // --- Logs ---
        var logsItem = new ToolStripMenuItem("Open Logs");
        logsItem.Click += (s, e) => OpenLogs();
        menu.Items.Add(logsItem);

        var clearLogsItem = new ToolStripMenuItem("Clear Logs");
        clearLogsItem.Click += (s, e) => ClearLogs();
        menu.Items.Add(clearLogsItem);

        menu.Items.Add(new ToolStripSeparator());

        // --- About ---
        var aboutItem = new ToolStripMenuItem("About");
        aboutItem.Click += (s, e) => ShowAbout();
        menu.Items.Add(aboutItem);

        // --- Quit ---
        var quit   = new ToolStripMenuItem("Quit");
        quit.Click += (s, e) => ExitApp();
        menu.Items.Add(quit);

        return menu;
    }

    private void SwitchDns(string providerName)
    {
        _dns.SwitchTo(providerName);
        _tray.ContextMenuStrip = BuildMenu();
        _tray.ShowBalloonTip(3000, "SekuraNetweaver", $"DNS switched to {providerName}", ToolTipIcon.Info);
    }

    private void OnSuspiciousProcess(string processName, string remoteIp, string hostName, bool isUdp, int localPort, string publisher)
    {
        _lastSuspiciousProcess = processName;
        
        // Update menu immediately if user right-clicks after notification
        _syncContext?.Post(_ => {
            _tray.ContextMenuStrip = BuildMenu();
        }, null);
 
        string displayHost = string.IsNullOrEmpty(hostName) ? remoteIp : $"{hostName} ({remoteIp})";
        string protocol = isUdp ? "UDP" : "TCP";
        string portInfo = localPort > 0 ? $" on {protocol} port {localPort}" : "";
        string publisherInfo = !string.IsNullOrEmpty(publisher) ? $"\n\nPublisher: {publisher}" : "\n\nPublisher: Unknown (Not Signed)";
 
        _tray.ShowBalloonTip(
            5000,
            "⚠️ Suspicious Connection",
            $"{processName} attempted an untrusted connection to {displayHost}{portInfo}.{publisherInfo}\n\nSekura Netweaver has logged this activity for your review.",
            ToolTipIcon.Warning
        );
    }

    private void OpenLogs()
    {
        string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SekuraNetweaver");
        string logPath = Path.Combine(appDataPath, "alerts.log");

        if (!Directory.Exists(appDataPath))
            Directory.CreateDirectory(appDataPath);

        if (!File.Exists(logPath))
            File.Create(logPath).Dispose();

        try {
            Process.Start(new ProcessStartInfo("notepad.exe", logPath) { UseShellExecute = true });
        } catch {
            // Fallback
        }
    }

    private void ClearLogs()
    {
        string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SekuraNetweaver");
        string logPath = Path.Combine(appDataPath, "alerts.log");

        var result = MessageBox.Show(
            "Are you sure you want to clear logs? You won't be able to retrieve them.",
            "Confirm Clear",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question
        );

        if (result == DialogResult.Yes)
        {
            try
            {
                File.WriteAllText(logPath, string.Empty);
                _tray.ShowBalloonTip(2000, "SekuraNetweaver", "Logs cleared successfully.", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error clearing logs: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void OpenWhitelist()
    {
        string appDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SekuraNetweaver");
        string whitelistPath = Path.Combine(appDataPath, "user-whitelist.txt");

        if (!Directory.Exists(appDataPath))
            Directory.CreateDirectory(appDataPath);

        if (!File.Exists(whitelistPath))
            File.WriteAllText(whitelistPath, "# Add process names to whitelist, one per line\r\n# Example: browser.exe\r\n");

        try {
            Process.Start(new ProcessStartInfo("notepad.exe", whitelistPath) { UseShellExecute = true });
        } catch {
            // Fallback
        }
    }

    private void ShowAbout()
    {
        using (var about = new AboutForm())
        {
            about.ShowDialog();
        }
    }

    private void ExitApp()
    {
        _process.Stop();
        _tray.Visible = false;
        Application.Exit();
    }
}


