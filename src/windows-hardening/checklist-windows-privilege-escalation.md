# Checkliste - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool, um nach lokalen Windows Privilege Escalation Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminformationen](windows-local-privilege-escalation/index.html#system-info)

- [ ] Beschaffe [**Systeminformationen**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Suche nach **Kernel-**[**Exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Google verwenden, um nach Kernel-Exploits zu suchen
- [ ] searchsploit verwenden, um nach Kernel-Exploits zu suchen
- [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter in der [**PowerShell-Historie**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Informationen in den [**Interneteinstellungen**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Laufwerke**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV-Aufklärung](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Prüfe [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)und [**WEF** ](windows-local-privilege-escalation/index.html#wef)-Einstellungen
- [ ] Prüfe [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Prüfe, ob [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktiv ist
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Prüfe, ob irgendein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) aktiv ist
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Benutzerrechte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Prüfe [**aktuelle** Benutzer**rechte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Prüfe, ob du eines dieser Tokens aktiviert hast: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Benutzer-Sitzungen**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Überprüfe [**Benutzer-Home-Verzeichnisse**](windows-local-privilege-escalation/index.html#home-folders) (Zugriff?)
- [ ] Prüfe die [**Passwortrichtlinie**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Was ist in der [**Zwischenablage**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Prüfe **aktuelle** [**Netzwerk** **Informationen**](windows-local-privilege-escalation/index.html#network)
- [ ] Prüfe versteckte lokale Services, die nach außen eingeschränkt sind

### [Laufende Prozesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Datei- und Ordnerberechtigungen von Prozess-Binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Passwortgewinnung im Speicher**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Unsichere GUI-Apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Anmeldeinformationen mit **interessanten Prozessen** via `ProcDump.exe` stehlen? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Kannst du **einen Service** ändern?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kannst du die **Binary** ändern, die von einem **Service** ausgeführt wird?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kannst du die **Registry** eines **Service** ändern?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kannst du einen **unquoted service binary path** ausnutzen?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] Service Triggers: aufzählen und privilegierte Dienste auslösen (service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Schreibrechte** bei installierten Anwendungen [**write permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Autostart-Anwendungen**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Verwundbare** [**Treiber**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kannst du **in einen Ordner innerhalb von PATH** schreiben?
- [ ] Gibt es einen bekannten Service-Binary, der versucht, eine nicht existente DLL zu laden?
- [ ] Kannst du **in einen Binary-Ordner** schreiben?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Das Netzwerk auflisten (Shares, Interfaces, Routen, Nachbarn, ...)
- [ ] Achte besonders auf Netzwerkdienste, die auf localhost (127.0.0.1) lauschen

### [Windows-Anmeldeinformationen](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) Anmeldeinformationen
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) Anmeldeinformationen, die du verwenden könntest?
- [ ] Interessante [**DPAPI**](windows-local-privilege-escalation/index.html#dpapi)-Anmeldeinformationen?
- [ ] Passwörter gespeicherter [**Wifi-Netzwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**kürzlich ausgeführten Befehlen**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) Passwörter?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Zugangsdaten?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Dateien und Registry (Anmeldeinformationen)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Zugangsdaten**](windows-local-privilege-escalation/index.html#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-Schlüssel in der Registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**Unattended-Dateien**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Irgendein [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) Backup?
- [ ] [**Cloud-Zugangsdaten**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) Datei?
- [ ] [**Zwischengespeichertes GPP-Passwort**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in der [**IIS Web config Datei**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Informationen in [**Web-Logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Möchtest du den Benutzer um [**Anmeldeinformationen**](windows-local-privilege-escalation/index.html#ask-for-credentials) bitten?
- [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Weitere [**Registry-Einträge mit Anmeldeinformationen**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**Browser-Daten**](windows-local-privilege-escalation/index.html#browsers-history) (DBs, Verlauf, Lesezeichen, ...)?
- [ ] [**Generische Passwortsuche**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in Dateien und Registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) zum automatischen Suchen nach Passwörtern

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hast du Zugriff auf einen Handle eines Prozesses, der vom Administrator ausgeführt wird?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Prüfe, ob du es ausnutzen kannst

{{#include ../banners/hacktricks-training.md}}
