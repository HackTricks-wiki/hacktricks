# Checkliste - Lokale Windows Privilegieneskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach Windows lokalen Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminfo](windows-local-privilege-escalation/#system-info)

- [ ] [**Systeminformationen**](windows-local-privilege-escalation/#system-info) abrufen
- [ ] Nach **Kernel** [**Exploits mit Skripten**](windows-local-privilege-escalation/#version-exploits) suchen
- [ ] **Google verwenden, um** nach Kernel **Exploits** zu suchen
- [ ] **searchsploit verwenden, um** nach Kernel **Exploits** zu suchen
- [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/#environment)?
- [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Interessante Informationen in [**Internet-Einstellungen**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Laufwerke**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Protokollierung/AV-Enumeration](windows-local-privilege-escalation/#enumeration)

- [ ] [**Audit**](windows-local-privilege-escalation/#audit-settings) und [**WEF**](windows-local-privilege-escalation/#wef) Einstellungen überprüfen
- [ ] [**LAPS**](windows-local-privilege-escalation/#laps) überprüfen
- [ ] Überprüfen, ob [**WDigest**](windows-local-privilege-escalation/#wdigest) aktiv ist
- [ ] [**LSA-Schutz**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Zwischengespeicherte Anmeldeinformationen**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Überprüfen, ob ein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker-Richtlinie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Benutzerprivilegien**](windows-local-privilege-escalation/#users-and-groups)
- [ ] [**Aktuelle** Benutzer **privilegien**](windows-local-privilege-escalation/#users-and-groups) überprüfen
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Überprüfen, ob du [eines dieser Tokens aktiviert hast](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Benutzersitzungen**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Überprüfen[ **Benutzerverzeichnisse**](windows-local-privilege-escalation/#home-folders) (Zugriff?)
- [ ] [**Passwortrichtlinie**](windows-local-privilege-escalation/#password-policy) überprüfen
- [ ] Was ist [**im Clipboard**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/#network)

- [ ] **Aktuelle** [**Netzwerkinformationen**](windows-local-privilege-escalation/#network) überprüfen
- [ ] **Versteckte lokale Dienste** überprüfen, die auf das Internet beschränkt sind

### [Ausgeführte Prozesse](windows-local-privilege-escalation/#running-processes)

- [ ] Berechtigungen für Prozessbinärdateien [**Datei- und Ordnersicherheiten**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Speicherpasswort-Mining**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Unsichere GUI-Apps**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Anmeldeinformationen mit **interessanten Prozessen** über `ProcDump.exe` stehlen? (firefox, chrome, usw...)

### [Dienste](windows-local-privilege-escalation/#services)

- [ ] [Kannst du **irgendeinen Dienst** **modifizieren**?](windows-local-privilege-escalation/#permissions)
- [ ] [Kannst du **die Binärdatei** modifizieren, die von einem **Dienst** **ausgeführt** wird?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Kannst du **die Registrierung** eines **Dienstes** **modifizieren**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Kannst du von einem **nicht zitierten Dienst** Binärdatei **Pfad** profitieren?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Anwendungen**](windows-local-privilege-escalation/#applications)

- [ ] **Schreib** [**berechtigungen für installierte Anwendungen**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Startup-Anwendungen**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Verwundbare** [**Treiber**](windows-local-privilege-escalation/#drivers)

### [DLL-Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Kannst du **in irgendeinen Ordner innerhalb von PATH** **schreiben**?
- [ ] Gibt es eine bekannte Dienstbinärdatei, die **versucht, eine nicht existierende DLL** zu laden?
- [ ] Kannst du **in irgendeinen** **Binärordner** **schreiben**?

### [Netzwerk](windows-local-privilege-escalation/#network)

- [ ] Das Netzwerk auflisten (Freigaben, Schnittstellen, Routen, Nachbarn, ...)
- [ ] Besonders auf Netzwerkdienste achten, die auf localhost (127.0.0.1) hören

### [Windows-Anmeldeinformationen](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) Anmeldeinformationen
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) Anmeldeinformationen, die du verwenden könntest?
- [ ] Interessante [**DPAPI-Anmeldeinformationen**](windows-local-privilege-escalation/#dpapi)?
- [ ] Passwörter von gespeicherten [**Wifi-Netzwerken**](windows-local-privilege-escalation/#wifi)?
- [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Passwörter in [**kürzlich ausgeführten Befehlen**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] [**Remote Desktop Credential Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) Passwörter?
- [ ] Existiert [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Anmeldeinformationen?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL-Seitenladung?

### [Dateien und Registrierung (Anmeldeinformationen)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Anmeldeinformationen**](windows-local-privilege-escalation/#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**SSH-Schlüssel in der Registrierung**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Passwörter in [**unbeaufsichtigten Dateien**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Gibt es ein [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) Backup?
- [ ] [**Cloud-Anmeldeinformationen**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) Datei?
- [ ] [**Zwischengespeichertes GPP-Passwort**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Passwort in [**IIS-Webkonfigurationsdatei**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Interessante Informationen in [**Webprotokollen**](windows-local-privilege-escalation/#logs)?
- [ ] Möchtest du [**den Benutzer nach Anmeldeinformationen fragen**](windows-local-privilege-escalation/#ask-for-credentials)?
- [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Andere [**Registrierungen mit Anmeldeinformationen**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Innerhalb [**von Browserdaten**](windows-local-privilege-escalation/#browsers-history) (Datenbanken, Verlauf, Lesezeichen, ...)?
- [ ] [**Allgemeine Passwortsuche**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in Dateien und Registrierung
- [ ] [**Tools**](windows-local-privilege-escalation/#tools-that-search-for-passwords) zur automatischen Suche nach Passwörtern

### [Leckende Handler](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Hast du Zugriff auf einen Handler eines Prozesses, der von einem Administrator ausgeführt wird?

### [Pipe-Client-Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Überprüfen, ob du es ausnutzen kannst

{{#include ../banners/hacktricks-training.md}}
