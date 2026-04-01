; Sekura Netweaver Inno Setup Script
; Build with Inno Setup 6 — run "dotnet publish" in Release mode first.

[Setup]
AppId={{D3B2A1E5-8C9B-4D3A-9F1E-7C2B5A4D3E1F}
AppName=Sekura Netweaver
AppVersion=1.4.3
AppPublisher=SekuraGuard
DefaultDirName={autopf}\Sekura Netweaver
DefaultGroupName=Sekura Netweaver
AllowNoIcons=yes
; Admin required: DNS switching via netsh needs elevation.
; The app itself also declares requiresAdministrator in its manifest.
PrivilegesRequired=admin
OutputDir=installer_output
OutputBaseFilename=SekuraNetweaver_Setup
SetupIconFile=Assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
; Elevated apps cannot use {userstartup} shortcuts — Windows will show a UAC prompt on every login.
; Task Scheduler with /rl highest is the correct mechanism for elevated auto-start.
Name: "startup"; Description: "Launch Sekura Netweaver on Windows Startup (runs elevated)"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
; Wildcard covers the .exe and all runtime dependencies from the publish output.
; No need to list the .exe separately.
Source: "bin\Release\net8.0-windows10.0.19041.0\win-x64\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sekura Netweaver"; Filename: "{app}\SekuraNetweaver.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,Sekura Netweaver}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Sekura Netweaver"; Filename: "{app}\SekuraNetweaver.exe"; Tasks: desktopicon; IconFilename: "{app}\icon.ico"

[Run]
; Register a scheduled task to auto-start with highest privileges on logon.
; This avoids UAC prompts on login that {userstartup} shortcuts trigger for elevated apps.
Filename: "schtasks.exe"; \
    Parameters: "/create /tn ""Sekura Netweaver Autostart"" /tr ""{app}\SekuraNetweaver.exe"" /sc onlogon /rl highest /f"; \
    Flags: runhidden; Tasks: startup

; Offer to launch after install
Filename: "{app}\SekuraNetweaver.exe"; \
    Description: "{cm:LaunchProgram,Sekura Netweaver}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the scheduled task on uninstall. /f suppresses "are you sure" prompts.
Filename: "schtasks.exe"; \
    Parameters: "/delete /tn ""Sekura Netweaver Autostart"" /f"; \
    Flags: runhidden; RunOnceId: "RemoveStartupTask"
