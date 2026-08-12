#ifndef DWI_VERSION
#define DWI_VERSION "1.0.0rc1"
#endif
#ifndef DWI_FILE_VERSION
#define DWI_FILE_VERSION "1.0.0.1"
#endif
#ifndef DWI_EXE
#define DWI_EXE "DWI-1.0.0rc1-Desktop.exe"
#endif

[Setup]
AppId={{A3F66504-DA7A-4AB0-9F75-10000000AC01}
AppName=DWI
AppVersion={#DWI_VERSION}
AppVerName=DWI {#DWI_VERSION}
AppPublisher=DWI contributors
DefaultDirName={localappdata}\DWI
DefaultGroupName=DWI
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=DWI-{#DWI_VERSION}-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#DWI_FILE_VERSION}
VersionInfoProductVersion={#DWI_FILE_VERSION}
LicenseFile=..\LICENSE

[Files]
Source: "{#DWI_EXE}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\DWI"; Filename: "{app}\DWI-{#DWI_VERSION}-Desktop.exe"
Name: "{autodesktop}\DWI"; Filename: "{app}\DWI-{#DWI_VERSION}-Desktop.exe"

[UninstallDelete]
Type: files; Name: "{app}\DWI-{#DWI_VERSION}-Desktop.exe"
Type: filesandordirs; Name: "{app}"
