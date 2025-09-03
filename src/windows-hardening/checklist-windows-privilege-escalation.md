# Checkliste - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool, um Windows local privilege escalation vectors zu finden:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Beschaffe [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Suche nach **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Verwende Google, um nach kernel exploits zu suchen
- [ ] Verwende searchsploit, um nach kernel exploits zu suchen
- [ ] Interessante Infos in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter in [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Infos in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Prüfe [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)und [**WEF** ](windows-local-privilege-escalation/index.html#wef)-Einstellungen
- [ ] Prüfe [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Prüfe, ob [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktiv ist
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Prüfe, ob irgendeine [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Prüfe die **aktuellen** Benutzer**privilegien**(windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Prüfe, ob du eines dieser Tokens aktiviert hast: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Prüfe [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (Zugriff?)
- [ ] Prüfe die [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Was ist [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Prüfe die **aktuellen** [**Network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Prüfe **versteckte lokale Dienste**, die nach außen beschränkt sind

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Zugriffsrechte auf Prozess-Binaries: [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Credentials stehlen mit **interessanten Prozessen** via `ProcDump.exe` ? (firefox, chrome, usw.)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Kannst du einen Dienst **modifizieren**? (Can you **modify any service**?)
- [ ] Kannst du die **binary**, die von einem Dienst **ausgeführt** wird, **ändern**? (Can you **modify** the **binary** that is **executed** by any **service**?)
- [ ] Kannst du die **Registry** eines Dienstes **ändern**? (Can you **modify** the **registry** of any **service**?)
- [ ] Kannst du von einem **unquoted service** binary **path** profitieren? (Can you take advantage of any **unquoted service** binary **path**?)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kannst du in irgendeinen Ordner innerhalb von PATH **schreiben**?
- [ ] Gibt es einen bekannten Service-Binary, der versucht, eine nicht-existente DLL zu laden?
- [ ] Kannst du in einen **Binaries-Ordner** **schreiben**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Netzwerk enumerieren (Shares, Interfaces, Routes, Neighbours, ...)
- [ ] Achte besonders auf Netzwerkdienste, die auf localhost (127.0.0.1) lauschen

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) Credentials, die du verwenden könntest?
- [ ] Interessante [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwörter von gespeicherten [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Infos in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) Passwörter?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Irgendein [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) Backup?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) Datei?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Infos in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Willst du den Benutzer nach [**credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) fragen?
- [ ] Interessante [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Andere [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in Dateien und Registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) zum automatischen Suchen nach Passwörtern

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hast du Zugriff auf irgendeinen Handler eines Prozesses, der von einem Administrator ausgeführt wird?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Prüfe, ob du es ausnutzen kannst

{{#include ../banners/hacktricks-training.md}}
