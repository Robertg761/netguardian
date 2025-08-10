; NetGuardian Windows Installer (Inno Setup)
; Build with Inno Setup Compiler (https://jrsoftware.org/isinfo.php)
; Place optional prerequisite installers in installers\prereqs (npcap.exe, nmap-setup.exe)

#define AppName "NetGuardian"
#define AppVersion "2.0"
#define Publisher "NetGuardian Team"
#define AppExe "NetGuardianGUI.exe"

[Setup]
AppId={{8D2B3B1D-9F2E-4E20-9C63-2E9D7F0C1A5A}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={pf}\{#AppName}
DefaultGroupName={#AppName}
OutputDir=installers\output
OutputBaseFilename=NetGuardian-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
DisableWelcomePage=no
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: desktopicon; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"

[Files]
; Main application files (built by PyInstaller)
Source: "..\dist\NetGuardianGUI.exe"; DestDir: "{app}"; Flags: ignoreversion
; Include any needed data files (packets, icons, etc.)
; Source: "..\assets\*"; DestDir: "{app}\assets"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\NetGuardian"; Filename: "{app}\{#AppExe}"
Name: "{commondesktop}\NetGuardian"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Optionally run pre-req installers if found in prereqs folder
Filename: "{tmp}\npcap-setup.exe"; Description: "Install Npcap (required for packet capture)"; Flags: shellexec waituntilterminated skipifsilent; Check: FileExists(ExpandConstant('{tmp}\npcap-setup.exe'))
Filename: "{tmp}\nmap-setup.exe"; Description: "Install Nmap (recommended for scanning)"; Flags: shellexec waituntilterminated skipifsilent; Check: FileExists(ExpandConstant('{tmp}\nmap-setup.exe'))

[Code]
function FileExists(const FileName: string): Boolean;
begin
  Result := FileSearch(FileName, '') <> '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  NpcapSrc, NmapSrc: string;
begin
  if CurStep = ssInstall then begin
    NpcapSrc := ExpandConstant('{src}\prereqs\npcap.exe');
    if FileExists(NpcapSrc) then
      ExtractTemporaryFile('npcap-setup.exe');

    NmapSrc := ExpandConstant('{src}\prereqs\nmap-setup.exe');
    if FileExists(NmapSrc) then
      ExtractTemporaryFile('nmap-setup.exe');
  end;
end;

