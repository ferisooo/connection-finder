; Installer for Connection Finder (built with Inno Setup 6).
; It installs just for the current user, so Windows doesn't ask for admin
; rights, and adds Start menu + desktop shortcuts.
;
; Build it after "flutter build windows --release" with:
;   ISCC.exe /DMyAppVersion=1.0.5 /DMyAppNumericVersion=1.0.5.0 windows\installer\connection_finder.iss

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#ifndef MyAppNumericVersion
  #define MyAppNumericVersion "1.0.0.0"
#endif

#define MyAppName "Connection Finder"
#define MyAppExeName "ConnectionFinder.exe"
#define BuildDir "..\..\build\windows\x64\runner\Release"

[Setup]
; Keep this id the same forever, so new versions replace the old one.
AppId={{8F6C2B1E-5A3D-4C7B-9E21-6D4F0A9B3C55}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=Connection Finder
AppPublisherURL=https://github.com/ferisooo/connection-finder
AppSupportURL=https://github.com/ferisooo/connection-finder/issues
VersionInfoVersion={#MyAppNumericVersion}
VersionInfoProductName={#MyAppName}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=lowest
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir=..\..\build\installer
OutputBaseFilename=ConnectionFinder-Setup
SetupIconFile=..\runner\resources\app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
WizardStyle=modern
WizardImageFile=wizard_large.bmp,wizard_large_250.bmp
WizardSmallImageFile=wizard_small.bmp,wizard_small_250.bmp
Compression=lzma2/max
SolidCompression=yes
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nConnection Finder shows which programs on your PC use the internet, and warns you if one looks suspicious.

[Tasks]
Name: "desktopicon"; Description: "Put a shortcut on my desktop"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#BuildDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Open Connection Finder now"; Flags: nowait postinstall skipifsilent
