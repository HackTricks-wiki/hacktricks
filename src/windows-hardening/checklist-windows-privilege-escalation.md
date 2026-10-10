# Checkliste - Lokale Windows-Privilege-Escalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach Vektoren für lokale Windows-Privilege-Escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminformationen](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Systeminformationen**](windows-local-privilege-escalation/index.html#system-info) abrufen
- [ ] Mit [**Skripten nach Kernel-Exploits suchen**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Mit **Google nach Kernel-Exploits suchen**
- [ ] Mit **searchsploit nach Kernel-Exploits suchen**
- [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Informationen in den [**Interneteinstellungen**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Laufwerke**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-Updater von Drittanbieter-Agenten / IPC-Missbrauch**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging-/AV-Aufzählung](windows-local-privilege-escalation/index.html#enumeration)

- [ ] [**Audit-**](windows-local-privilege-escalation/index.html#audit-settings) und [**WEF-**](windows-local-privilege-escalation/index.html#wef)Einstellungen überprüfen
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) überprüfen
- [ ] Prüfen, ob [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) aktiv ist
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Zwischengespeicherte Anmeldedaten**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Prüfen, ob ein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker-Richtlinie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / stille Erhöhung über UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Registry-Propagation der Barrierefreiheit auf dem Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Benutzerrechte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**Rechte**](windows-local-privilege-escalation/index.html#users-and-groups) des **aktuellen** Benutzers überprüfen
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Prüfen, ob eines [dieser Tokens aktiviert ist](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Prüfen, ob du [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) hast, um Raw-Volumes zu lesen und Datei-ACLs zu umgehen
- [ ] [**Benutzersitzungen**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**Benutzerverzeichnisse**](windows-local-privilege-escalation/index.html#home-folders) überprüfen (Zugriff?)
- [ ] [**Kennwortrichtlinie**](windows-local-privilege-escalation/index.html#password-policy) überprüfen
- [ ] Was befindet sich[ **in der Zwischenablage**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] **Aktuelle** [**Netzwerkinformationen**](windows-local-privilege-escalation/index.html#network) überprüfen
- [ ] Nach **verborgenen lokalen Diensten** suchen, die von außen nicht erreichbar sind

### [Laufende Prozesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Berechtigungen für Dateien und Ordner**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) der Prozess-Binaries überprüfen
- [ ] [**Passwort-Mining aus dem Arbeitsspeicher**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Unsichere GUI-Apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Mit `ProcDump.exe` Anmeldedaten aus **interessanten Prozessen** stehlen? (Firefox, Chrome usw.)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kannst du **einen Dienst ändern**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kannst du die **Binärdatei** ändern, die von einem **Dienst** **ausgeführt** wird?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kannst du die **Registry** eines **Dienstes** ändern?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kannst du einen **nicht in Anführungszeichen gesetzten Dienst-Binärpfad** ausnutzen?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: privilegierte Dienste auflisten und auslösen](windows-local-privilege-escalation/service-triggers.md)

### [**Anwendungen**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Schreib**[**berechtigungen für installierte Anwendungen**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startanwendungen**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Verwundbare** [**Treiber**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kannst du in einen **Ordner innerhalb von PATH schreiben**?
- [ ] Gibt es eine bekannte Dienst-Binärdatei, die versucht, eine **nicht vorhandene DLL zu laden**?
- [ ] Kannst du in einen **Binärdateiordner** schreiben?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Das Netzwerk auflisten (Freigaben, Schnittstellen, Routen, Nachbarn usw.)
- [ ] Netzwerkdiensten besondere Aufmerksamkeit schenken, die auf localhost (127.0.0.1) lauschen

### [Windows-Anmeldedaten](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)-Anmeldedaten
- [ ] Gibt es [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)-Anmeldedaten, die du verwenden könntest?
- [ ] Interessante [**DPAPI-Anmeldedaten**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwörter gespeicherter [**WLAN-Netzwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**zuletzt ausgeführten Befehlen**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwörter im [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Ist [**AppCmd.exe** vorhanden](windows-local-privilege-escalation/index.html#appcmd-exe)? Anmeldedaten?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Dateien und Registry (Anmeldedaten)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Anmeldedaten**](windows-local-privilege-escalation/index.html#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-Schlüssel in der Registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**unbeaufsichtigten Installationsdateien**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Gibt es eine [**SAM- und SYSTEM-Sicherung**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Wenn [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) vorhanden ist, Raw-Volumes auf `SAM`, `SYSTEM`, DPAPI-Material und `MachineKeys` auslesen
- [ ] [**Cloud-Anmeldedaten**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee-SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)-Datei?
- [ ] [**Zwischengespeichertes GPP-Passwort**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in einer [**IIS-Webkonfigurationsdatei**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Informationen in [**Web-Logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Möchtest du den Benutzer [**nach Anmeldedaten fragen**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Weitere [**Registry-Einträge mit Anmeldedaten**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**Browserdaten**](windows-local-privilege-escalation/index.html#browsers-history) (Datenbanken, Verlauf, Lesezeichen usw.)?
- [ ] [**Allgemeine Passwortsuche**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in Dateien und Registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) zur automatischen Passwortsuche

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hast du Zugriff auf einen Handler eines von einem Administrator ausgeführten Prozesses?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Prüfen, ob du das ausnutzen kannst

## References

- [1] [Project Zero - Umgehen des Administrator Protection durch Missbrauch von UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
