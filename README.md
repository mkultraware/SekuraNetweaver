# SekuraNetweaver 🛡️

**SekuraNetweaver** is a lightweight, low-level network monitoring and security utility for Windows. It provides transparent visibility into process-to-network mappings, identifies suspicious connection patterns using advanced heuristics, and empowers users to reclaim their network privacy through an integrated DNS switcher.

---

## 🚀 Key Features

### 1. Advanced Process Monitoring
Unlike standard diagnostic tools, SekuraNetweaver implements a **"Trust Pipeline"** to identify suspicious outbound traffic in real-time.
- **PowerShell-Backed Ingestion**: Uses `Get-NetTCPConnection` to reliably map active sockets to PIDs across all TCP/UDP states.
- **Authenticode Verification**: Automatically trusts connections from reputable publishers (Microsoft, Valve, Google, etc.) using digital signature validation (`X509Certificate`).
- **Heuristic Detection**: Flags binaries running from volatile paths (`\Temp\`, `\Users\Public\`) or those missing valid signatures.
- **PS Script Auditing**: Specifically identifies and reports the exact `.ps1` or `.psm1` file being executed by PowerShell instances.

### 2. Privacy-First DNS Switching
One-click toggling between high-performance, privacy-respecting DNS providers. Automatically caches and restores original network settings.
- **Integrated Log Management**: Directly access and **clear** persistent logs from the tray menu to keep your system clean.
- **No Telemetry**: Your logs and whitelists stay on your machine. SekuraNetweaver is 100% local-only.

### 3. Smart WiFi Auditing
Real-time analysis of wireless security properties using the Native Wifi API.
- **Security Logic**: Flags legacy protocols (802.11b/g) and reports encryption standards (WPA2/WPA3).
- **Proactive Warnings**: Visual indicators for "Open" or "WEP" networks that put your data at risk.

---

## 🛠 Architecture & Design

SekuraNetweaver is built on **.NET 8.0** with a focus on a **Zero-Telemetry, Local-Only** philosophy.

- **Non-Intrusive Design**: The app is 100% passive; it monitors and alerts without intercepting or terminating traffic, ensuring 0% impact on game performance or system stability.
- **Single-Instance Lifecycle**: Enforced via a `GlobalMutex` (AppGuid-based) to prevent resource contention.
- **Real-Time Configuration**: Uses a `FileSystemWatcher` to reload user whitelists instantly without restarting the application.

---

## 📦 Installation & Deployment

### Download the Application
Pre-compiled binaries and the installer are available in the [**Releases**](https://github.com/mkultraware/SekuraNetweaver/releases) section. 

### Build from Source
**Requirements:**
- Windows 10/11 (x64)
- .NET 8.0 SDK

```powershell
# Publish a standalone version
dotnet publish -r win-x64 -c Release --self-contained false
```

### Create the Installer
We use **Inno Setup 6** for professional deployments.
1. Open `installer.iss`.
2. Ensure you have built the application in `Release` mode.
3. Click **Compile** to generate `SekuraNetweaver_Setup.exe` in the `installer_output/` folder.

---

## 📂 Configuration
The application stores all local persistent data in `%LocalAppData%\SekuraNetweaver\`:
- `alerts.log`: Historical record of suspicious connection attempts.
- `user-whitelist.txt`: User-defined process exceptions.

---

## ⚖️ License & Privacy
- **Privacy**: No data ever leaves your machine. Logs are stored locally and are never uploaded to any server.
- **Usage**: Provided "as-is" for personal security auditing.

*Developed by mkultraware.*
