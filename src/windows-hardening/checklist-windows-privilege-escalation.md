# Checklist - Lokale Windows-Privilegieneskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool, um nach Windows local privilege escalation vectors zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**System information**](windows-local-privilege-escalation/index.html#system-info) ermitteln
- [ ] Nach **kernel**-[**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) suchen
- [ ] **Google verwenden, um** nach kernel-**exploits** zu suchen
- [ ] **searchsploit verwenden, um** nach kernel-**exploits** zu suchen
- [ ] Interessante Infos in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter in der [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Infos in den [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) und [**WEF** ](windows-local-privilege-escalation/index.html#wef)-Einstellungen prüfen
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) prüfen
- [ ] Prüfen, ob [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktiv ist
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Prüfen, ob irgendein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups) prüfen
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Prüfen, ob eines dieser Tokens aktiviert ist: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Prüfen, ob du [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) hast, um Raw Volumes zu lesen und file ACLs zu umgehen
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**users homes**](windows-local-privilege-escalation/index.html#home-folders) prüfen (Zugriff?)
- [ ] [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy) prüfen
- [ ] Was ist [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Die aktuelle [**network** **information**](windows-local-privilege-escalation/index.html#network) prüfen
- [ ] Versteckte lokale Services prüfen, die nach außen eingeschränkt sind

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Prozess-Binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Anmeldedaten mit **interessanten Prozessen** via `ProcDump.exe` stehlen ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Kannst du **irgendeinen service modifizieren**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Kannst du das **binary** modifizieren, das von einem **service** **ausgeführt** wird?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Kannst du die **registry** eines **service** modifizieren?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Kannst du einen **unquoted service** binary **path** ausnutzen?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privileged services enumerieren und triggern](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write**-[**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kannst du in irgendeinen Ordner innerhalb von PATH **schreiben**?
- [ ] Gibt es ein bekanntes Service-Binary, das versucht, eine nicht-existierende DLL zu laden?
- [ ] Kannst du in irgendeinen **binaries folder** **schreiben**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Das Netzwerk enumerieren (Shares, Interfaces, Routen, Nachbarn, ...)
- [ ] Einen besonderen Blick auf Network Services werfen, die auf localhost (127.0.0.1) lauschen

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)Anmeldedaten
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) Anmeldedaten, die du nutzen könntest?
- [ ] Interessante [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwörter gespeicherter [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Infos in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwörter im [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Existiert [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Anmeldedaten?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **und** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Irgendein Backup von [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Wenn [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) vorhanden ist, versuche Raw-Volume-Reads für `SAM`, `SYSTEM`, DPAPI-Material und `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) Datei?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Infos in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Möchtest du den Benutzer nach [**credentials fragen**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interessante [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Andere [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In den [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (DBs, History, Bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in files and registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) zum automatischen Suchen nach Passwörtern

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hast du Zugriff auf einen Handler eines Prozesses, der als Administrator läuft?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Prüfen, ob du es missbrauchen kannst



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
