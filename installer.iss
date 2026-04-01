; Sekura Netweaver Inno Setup Script
; Use the Inno Setup Compiler to build the installer (installer.exe)

[Setup]
AppId={{D3B2A1E5-8C9B-4D3A-9F1E-7C2B5A4D3E1F}
AppName=Sekura Netweaver
AppVersion=1.3.2
AppPublisher=SekuraGuard
DefaultDirName={autopf}\Sekura Netweaver
DefaultGroupName=Sekura Netweaver
AllowNoIcons=yes
; Require admin for DNS switching capabilities
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
Name: "startup"; Description: "Launch Sekura Netweaver on Windows Startup"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
; Source files from the publish directory
Source: "bin\Release\net8.0-windows10.0.19041.0\win-x64\publish\SekuraNetweaver.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\net8.0-windows10.0.19041.0\win-x64\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Include the icon for shortcuts
Source: "Assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
; Documentation
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sekura Netweaver"; Filename: "{app}\SekuraNetweaver.exe"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,Sekura Netweaver}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Sekura Netweaver"; Filename: "{app}\SekuraNetweaver.exe"; Tasks: desktopicon; IconFilename: "{app}\icon.ico"
Name: "{userstartup}\Sekura Netweaver"; Filename: "{app}\SekuraNetweaver.exe"; Tasks: startup; IconFilename: "{app}\icon.ico"

[Run]
Filename: "{app}\SekuraNetweaver.exe"; Description: "{cm:LaunchProgram,Sekura Netweaver}"; Flags: nowait postinstall skipifsilent
