; Inno Setup script for PrivateFirewall — a signed, single-file Windows installer.
; This app controls the Windows firewall, so it installs machine-wide and
; ELEVATES (admin). Ships the engine exe, the PowerShell tooling, the dashboard,
; and the QuickOpen Root CA. Compiled and Authenticode-signed in CI.
;
; Expects packaging\staging\ to hold: PrivateFirewall.exe, *.ps1, Install.cmd,
; dashboard.html, README.md, FEATURES.md, LICENSE, quickopen-root.crt.

#define AppName "PrivateFirewall"
#define AppVersion "1.0.3"
#define AppPublisher "QuickOpen (quickopen.ai)"
#define AppURL "https://quickopen.ai/projects/private-firewall"

[Setup]
AppMutex=QuickOpen.PrivateFirewall
AppId={{C4E1F2A9-7B63-4D5E-9A1C-2F8B0D3E4A61}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\PrivateFirewall
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\PrivateFirewall.exe
OutputDir=dist
OutputBaseFilename=PrivateFirewall-Setup
SetupIconFile=..\private-firewall.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=branding\wizard-large.bmp
WizardSmallImageFile=branding\wizard-small.bmp
AppCopyright=Apache-2.0. 100%% AI-built, published on QuickOpen (quickopen.ai).
VersionInfoCompany=QuickOpen
VersionInfoProductName=PrivateFirewall
VersionInfoVersion=1.0.3.0
; Firewall control requires administrator rights.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=PrivateFirewall is a 100%% AI-built, open-source control plane and intrusion-alert dashboard for the Windows firewall, published on QuickOpen (quickopen.ai).%n%nIt runs entirely on this PC and needs administrator rights to manage the firewall.
BeveledLabel=QuickOpen · quickopen.ai

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "trustca"; Description: "Trust the QuickOpen Root CA (lets Windows verify QuickOpen signatures)"; GroupDescription: "Security:"; Flags: unchecked
Name: "bootlockdown"; Description: "Enforce default-deny-outbound at boot (persistent firewall lockdown). Advanced — you can undo this anytime from the app or Revert-PrivateFirewall.ps1."; GroupDescription: "Firewall:"; Flags: unchecked

[Files]
Source: "staging\PrivateFirewall.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\dashboard.html"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\*.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\Install.cmd"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\quickopen-root.crt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist
Source: "staging\FEATURES.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\PrivateFirewall"; Filename: "{app}\PrivateFirewall.exe"; IconFilename: "{app}\PrivateFirewall.exe"
Name: "{group}\Uninstall PrivateFirewall"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PrivateFirewall"; Filename: "{app}\PrivateFirewall.exe"; IconFilename: "{app}\PrivateFirewall.exe"; Tasks: desktopicon

[Run]
Filename: "certutil.exe"; Parameters: "-addstore Root ""{app}\quickopen-root.crt"""; Tasks: trustca; Flags: runhidden; StatusMsg: "Trusting the QuickOpen Root CA..."
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Install-PrivateFirewall.ps1"" -BootLockdown"; Tasks: bootlockdown; Flags: runhidden; StatusMsg: "Arming boot-time default-deny outbound..."
Filename: "{app}\PrivateFirewall.exe"; Description: "Launch PrivateFirewall now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Tear down the firewall rules, scheduled tasks and boot lockdown this app added.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Revert-PrivateFirewall.ps1"" -Revert -Uninstall"; Flags: runhidden skipifdoesntexist; RunOnceId: "PfwRevert"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\PrivateFirewall"

[Code]
// On uninstall, offer to also remove the QuickOpen Root CA (opt-in; other
// QuickOpen apps may rely on it).
