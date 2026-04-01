# SekuraNetweaver (v1.4.3)
[![VirusTotal Scan](https://img.shields.io/badge/VirusTotal-Clean-green)](https://www.virustotal.com/gui/file/d4a95a7d30849602931c2b09ebad7f1a9f52e6526669da19720e81a843e0b65c/detection)

SekuraNetweaver is a lightweight, low-level network monitoring and security utility for Windows. It provides transparent visibility into processnd-to-network mappings, identifies suspicious connection patterns using advanced heuristics, and empowers users to manage their network privacy through an integrated, locale-independent DNS switcher.

---

## Key Features

### 1. High-Performance Process Monitoring
SekuraNetweaver implements a multi-stage Trust Pipeline to identify suspicious outbound traffic in real-time.
- **Kernel-Direct Ingestion**: Uses high-performance P/Invoke (GetExtendedTcpTable) to map active sockets to PIDs without shell overhead.
- **Authenticode Signature Verification**: Automatically verifies digital signatures to distinguish between reputable software (Microsoft, Google, Valve, etc.) and unsigned binaries.
- **Path Heuristics**: Binaries running from volatile paths (e.g., \Temp\, \Users\Public\) trigger security alerts even if they are digitally signed.

### 2. High-Performance Audit Mode (v1.4.3)
To balance security with user convenience, v1.4.3 enhances "Audit Mode" for Living Off the Land Binaries (LOLBins) with native WMI-based process auditing.
- **WMI-Native Inspection**: Replaced expensive PowerShell-based command line checks with a high-performance WMI (Windows Management Instrumentation) backend, reducing CPU overhead by ~90% during monitoring.
- **Forensic Trail**: Microsoft-signed LOLBins in clean system paths are logged to the audit trail (alerts.log) for review.
- **Suppressed Notifications**: These signed system connections do not trigger balloon notifications, preventing "notification storms" during system updates or normal administrative activity.
- **Strict Alerts**: Unsigned LOLBins or those running from suspicious directories still trigger a full critical alert and user notification.

### 3. Locale-Independent DNS Switching
Integrated WMI-based DNS management for privacy-respecting providers (Cloudflare, Quad9, Google).
- **Stability**: Uses WMI (Win32_NetworkAdapterConfiguration) instead of netsh, ensuring the feature works correctly on non-English Windows installations (e.g., Swedish, German, Japanese).
- **Original Restore**: Caches and restores original network configurations (DHCP or Static) with single-click precision.

### 4. Native WiFi Auditing
Real-time analysis of wireless security properties using the ManagedNativeWifi API.
- **Deep Inspection**: Correctly identifies WPA2, WPA3, and OWE encryption standards.
- **Security Visibility**: Provides clear visual indicators for insecure or open networks.

---

## Known Issues

- **Notification Storms**: If an unsigned application or a binary running from a temporary directory makes a high volume of concurrent connections, it may trigger multiple balloon notifications. The app includes a 5-minute deduplication window per process/IP/port to mitigate this.
- **Log File Growth**: Because Audit Mode logs all certified LOLBin activity (like msiexec during Windows Updates), the alerts.log file can grow over time. It is recommended to use the "Clear Logs" feature occasionally.
- **Developer False Positives**: Certain developer tools, compilers, or IDE extensions running from AppData or LocalTemp may trigger alerts unless explicitly added to the user-whitelist.txt.

---

## Installation and Deployment

### Automated Deployment
The provided installer (installer.iss) configures a Windows Scheduled Task for the application. This allows SekuraNetweaver to start at login with "Highest Privileges," bypassing the standard UAC prompt for a seamless, silent startup.

### Build from Source
- **Platform**: Windows 10/11 (x64)
- **Framework**: .NET 8.0 SDK

```powershell
# Publish standalone release version
dotnet publish -c Release -r win-x64 --self-contained
```

---

## Configuration
Local persistent data is stored in %LocalAppData%\SekuraNetweaver\:
- **alerts.log**: Historical record of suspicious and audited connection attempts.
- **user-whitelist.txt**: User-defined process exceptions (one process name per line).
- **user-domains.txt**: Trusted domains for DNS resolution context.

Developed by mkultraware.
Licensed for personal use. Contact founder@sekura.se for commercial inquiries.
