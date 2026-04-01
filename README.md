# SekuraNetweaver 🛡️

**SekuraNetweaver** is a lightweight, low-level network monitoring and security utility for Windows. It provides transparent visibility into process-to-network mappings, identifies suspicious connection patterns using advanced heuristics, and empowers users to reclaim their network privacy through an integrated DNS switcher.

---

## 🚀 Key Features

### 1. Advanced Process Monitoring
SekuraNetweaver implements a **"Trust Pipeline"** to identify suspicious outbound traffic in real-time.
- **Kernel-Direct Ingestion (v1.4+)**: Uses high-performance P/Invoke (`GetExtendedTcpTable`) to map active sockets to PIDs without the overhead or latency of PowerShell.
- **Trust-All-Signed Model (v1.4.1)**: Automatically trusts connections from any binary with a valid digital signature (Mozilla, Steam, NVIDIA, etc.) to eliminate false positives.
- **Implicit Path Trust**: Silently trusts admin-installed software (`C:\Program Files`) and Developer Extensions (`.vscode\extensions`).
- **Path Heuristics**: Even if signed, binaries running from volatile paths (`\Temp\`, `\Users\Public\`) still trigger a security alert.

### 2. Privacy-First DNS Switching
One-click toggling between high-performance, privacy-respecting DNS providers.
- **DHCP & Static Awareness**: Intelligent switching that detects and restores your network's original configuration (DHCP or Static IP).
- **No Telemetry**: Your logs and whitelists stay on your machine. SekuraNetweaver is 100% local-only.

### 3. Smart WiFi Auditing (v1.4+)
Real-time analysis of wireless security properties using the `ManagedNativeWifi` library.
- **Security Logic**: Correctly identifies and reports actual encryption standards (**WPA2**, **WPA3**, **Open**) for the active connection.
- **Proactive Warnings**: Visual indicators for insecure networks that put your data at risk.

---

## 🛠 Architecture & Design

SekuraNetweaver is built on **.NET 8.0** with a focus on a **Native, High-Performance** philosophy.

- **Non-Intrusive Design**: The app is 100% passive; it monitors and alerts without intercepting or terminating traffic.
- **Elevated Persistence (v1.4+)**: Installs via a **Windows Scheduled Task** for silent, elevated autostart at login without UAC prompts.
- **Real-Time Configuration**: Uses a `FileSystemWatcher` to reload user whitelists instantly.

---

## 📦 Installation & Deployment

### Download the Application
Pre-compiled binaries and the installer are available in the [**Releases**](https://github.com/mkultraware/SekuraNetweaver/releases) section. 

### Build from Source
**Requirements:**
- Windows 10/11 (x64)
- .NET 8.0 SDK

```powershell
# Publish v1.4.1 standalone version
dotnet publish -r win-x64 -c Release --self-contained false
```

### Create the Installer
We use **Inno Setup 6** for professional deployments.
1. Open `installer.iss`.
2. Ensure you have built the application in `Release` mode.
3. Click **Compile** to generate `SekuraNetweaver_Setup.exe`.

---

## 📂 Configuration
The application stores all local persistent data in `%LocalAppData%\SekuraNetweaver\`:
- `alerts.log`: Historical record of suspicious connection attempts.
- `user-whitelist.txt`: User-defined process exceptions.

---

## ⚖️ License & Privacy
- **Privacy**: No data ever leaves your machine. Logs are stored locally and are never uploaded to any server.
- **Usage**: 
  - **Free for personal use.**
  - **For business usage, please contact: [founder@sekura.se](mailto:founder@sekura.se)**

*Developed by mkultraware.*
