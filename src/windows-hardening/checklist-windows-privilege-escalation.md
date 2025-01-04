# Checkliste - Lokale Windows Privilegieneskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach Windows lokalen Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminfo](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Systeminformationen**](windows-local-privilege-escalation/index.html#system-info) abrufen
- [ ] Nach **Kernel** [**Exploits mit Skripten**](windows-local-privilege-escalation/index.html#version-exploits) suchen
- [ ] **Google verwenden, um nach** Kernel **Exploits** zu suchen
- [ ] **searchsploit verwenden, um nach** Kernel **Exploits** zu suchen
- [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Informationen in [**Internet-Einstellungen**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Laufwerke**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Protokollierung/AV-Enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) und [**WEF**](windows-local-privilege-escalation/index.html#wef) Einstellungen überprüfen
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) überprüfen
- [ ] Überprüfen, ob [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) aktiv ist
- [ ] [**LSA-Schutz**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Zwischengespeicherte Anmeldeinformationen**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Überprüfen, ob ein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker-Richtlinie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Benutzerprivilegien**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**Aktuelle** Benutzer **privilegien**](windows-local-privilege-escalation/index.html#users-and-groups) überprüfen
- [ ] Sind Sie [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Überprüfen, ob Sie [eines dieser Tokens aktiviert haben](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Benutzersitzungen**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Überprüfen[ **Benutzerverzeichnisse**](windows-local-privilege-escalation/index.html#home-folders) (Zugriff?)
- [ ] [**Passwortrichtlinie**](windows-local-privilege-escalation/index.html#password-policy) überprüfen
- [ ] Was ist [**in der Zwischenablage**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] **Aktuelle** [**Netzwerkinformationen**](windows-local-privilege-escalation/index.html#network) überprüfen
- [ ] **Versteckte lokale Dienste** überprüfen, die auf das Internet beschränkt sind

### [Ausgeführte Prozesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Prozesse Binärdateien [**Datei- und Ordnersicherheitsberechtigungen**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Speicherpasswort-Mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Unsichere GUI-Apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Anmeldeinformationen mit **interessanten Prozessen** über `ProcDump.exe` stehlen? (firefox, chrome, usw...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Können Sie **irgendeinen Dienst** ändern?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Können Sie **die Binärdatei** ändern, die von einem **Dienst** **ausgeführt** wird?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Können Sie **die Registrierung** eines **Dienstes** ändern?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Können Sie von einem **nicht zitierten Dienst** Binärdateipfad profitieren?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Anwendungen**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Schreib** [**Berechtigungen für installierte Anwendungen**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup-Anwendungen**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Verwundbare** [**Treiber**](windows-local-privilege-escalation/index.html#drivers)

### [DLL-Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Können Sie **in einen beliebigen Ordner im PATH schreiben**?
- [ ] Gibt es eine bekannte Dienstbinärdatei, die **versucht, eine nicht existierende DLL zu laden**?
- [ ] Können Sie **in einen beliebigen** Binärdateiordner **schreiben**?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Das Netzwerk auflisten (Freigaben, Schnittstellen, Routen, Nachbarn, ...)
- [ ] Besonders auf Netzwerkdienste achten, die auf localhost (127.0.0.1) hören

### [Windows-Anmeldeinformationen](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) Anmeldeinformationen
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) Anmeldeinformationen, die Sie verwenden könnten?
- [ ] Interessante [**DPAPI-Anmeldeinformationen**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwörter von gespeicherten [**WLAN-Netzwerken**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**kürzlich ausgeführten Befehlen**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credential Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) Passwörter?
- [ ] [**AppCmd.exe** existiert](windows-local-privilege-escalation/index.html#appcmd-exe)? Anmeldeinformationen?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL-Seitenladung?

### [Dateien und Registrierung (Anmeldeinformationen)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Anmeldeinformationen**](windows-local-privilege-escalation/index.html#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-Schlüssel in der Registrierung**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**unbeaufsichtigten Dateien**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Irgendein [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) Backup?
- [ ] [**Cloud-Anmeldeinformationen**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) Datei?
- [ ] [**Zwischengespeichertes GPP-Passwort**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in [**IIS-Webkonfigurationsdatei**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Informationen in [**Webprotokollen**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Möchten Sie [**den Benutzer nach Anmeldeinformationen fragen**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Andere [**Registrierungen mit Anmeldeinformationen**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**Browserdaten**](windows-local-privilege-escalation/index.html#browsers-history) (Datenbanken, Verlauf, Lesezeichen, ...)?
- [ ] [**Allgemeine Passwortsuche**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in Dateien und Registrierung
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) zur automatischen Passwortsuche

### [Leckende Handler](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Haben Sie Zugriff auf einen Handler eines Prozesses, der von einem Administrator ausgeführt wird?

### [Pipe-Client-Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Überprüfen, ob Sie es ausnutzen können

{{#include ../banners/hacktricks-training.md}}
