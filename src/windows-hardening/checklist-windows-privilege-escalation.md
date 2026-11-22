# Checkliste - lokale Windows-Privilege-Eskalation

{{#include ../banners/hacktricks-training.md}}

### **Bestes Tool zum Suchen nach Vektoren für die lokale Windows-Privilege-Eskalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Systeminformationen](windows-local-privilege-escalation/index.html#system-info)

- [ ] [**Systeminformationen**](windows-local-privilege-escalation/index.html#system-info) abrufen
- [ ] Mit [**Skripten**](windows-local-privilege-escalation/index.html#version-exploits) nach **Kernel-Exploits** suchen
- [ ] Mit **Google nach Kernel-Exploits suchen**
- [ ] Mit **searchsploit nach Kernel-Exploits suchen**
- [ ] Interessante Informationen in [**Umgebungsvariablen**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwörter im [**PowerShell-Verlauf**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante Informationen in den [**Interneteinstellungen**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Laufwerke**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS-Exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-Updater von Drittanbieter-Agenten / IPC-Missbrauch**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Protokollierungs-/AV-Aufzählung](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Einstellungen für [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)und [**WEF** ](windows-local-privilege-escalation/index.html#wef)überprüfen
- [ ] [**LAPS**](windows-local-privilege-escalation/index.html#laps) überprüfen
- [ ] Prüfen, ob [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktiv ist
- [ ] [**LSA-Schutz**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Zwischengespeicherte Anmeldedaten**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Prüfen, ob ein [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) vorhanden ist
- [ ] [**AppLocker-Richtlinie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin-Schutz / stille Erhöhung über UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Registry-Propagation über Barrierefreiheit auf dem sicheren Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Benutzerrechte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] [**Berechtigungen**](windows-local-privilege-escalation/index.html#users-and-groups) des **aktuellen** Benutzers überprüfen
- [ ] Bist du [**Mitglied einer privilegierten Gruppe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Prüfen, ob diese [Berechtigungen im aktuellen Token vorhanden sind](windows-local-privilege-escalation/access-tokens.md), auch wenn sie als **Disabled** angezeigt werden: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Eine deaktivierte Berechtigung kann nur aktiviert werden, wenn sie bereits im Token enthalten ist.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Prüfen, ob [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) als Berechtigung zur Volume-Wartung vorhanden ist. Diese Berechtigung allein gewährt keinen Lesezugriff auf Raw-Volumes; für das Öffnen eines Datenträgers oder Volumes gelten separate Zugriffsanforderungen.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Benutzersitzungen**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] [**Benutzerverzeichnisse**](windows-local-privilege-escalation/index.html#home-folders) überprüfen (Zugriff?)
- [ ] [**Passwortrichtlinie**](windows-local-privilege-escalation/index.html#password-policy) überprüfen
- [ ] Was befindet sich[ **in der Zwischenablage**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] **Aktuelle** [**Netzwerkinformationen**](windows-local-privilege-escalation/index.html#network) überprüfen
- [ ] Nach **verborgenen lokalen Diensten** suchen, die von außen eingeschränkt sind

### [Laufende Prozesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Datei- und Ordnerberechtigungen**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) der Prozess-Binärdateien
- [ ] [**Passwörter aus dem Arbeitsspeicher auslesen**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Unsichere GUI-Apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Anmeldedaten aus **interessanten Prozessen** mit `ProcDump.exe` stehlen? (firefox, chrome usw. ...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kannst du einen **Dienst ändern**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kannst du die von einem **Dienst** **ausgeführte** **Binärdatei** ändern?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kannst du die **Registry** eines **Dienstes** ändern?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kannst du einen **Dienst** mit **nicht in Anführungszeichen gesetztem Binärpfad** ausnutzen?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service-Trigger: privilegierte Dienste auflisten und auslösen](windows-local-privilege-escalation/service-triggers.md)

### [**Anwendungen**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Schreibberechtigungen** für [**installierte Anwendungen**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Anwendungen beim Systemstart**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Verwundbare** [**Treiber**](windows-local-privilege-escalation/index.html#drivers)

### [DLL-Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kannst du in einen beliebigen Ordner innerhalb von PATH **schreiben**?
- [ ] Gibt es eine bekannte Dienst-Binärdatei, die versucht, eine **nicht vorhandene DLL zu laden**?
- [ ] Kannst du in einen beliebigen **Binärdateiordner schreiben**?

### [Netzwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Netzwerk auflisten (Freigaben, Schnittstellen, Routen, Nachbarn, ...)
- [ ] Besonders auf Netzwerkdienste achten, die auf localhost (127.0.0.1) lauschen

### [Windows-Anmeldedaten](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)-Anmeldedaten
- [ ] Gibt es [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)-Anmeldedaten, die du verwenden könntest?
- [ ] Interessante [**DPAPI-Anmeldedaten**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwörter gespeicherter [**WLAN-Netzwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante Informationen in [**gespeicherten RDP-Verbindungen**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwörter in [**zuletzt ausgeführten Befehlen**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwörter im [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Ist [**AppCmd.exe vorhanden**](windows-local-privilege-escalation/index.html#appcmd-exe)? Anmeldedaten?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) vorhanden? DLL Side Loading?

### [Dateien und Registry (Anmeldedaten)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Anmeldedaten**](windows-local-privilege-escalation/index.html#putty-creds) **und** [**SSH-Hostschlüssel**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-Schlüssel in der Registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwörter in [**unbeaufsichtigten Installationsdateien**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Gibt es ein [**SAM- und SYSTEM-**](windows-local-privilege-escalation/index.html#sam-and-system-backups)-Backup?
- [ ] Wenn ein lesbarer Raw-Volume-Handle unabhängig davon zugänglich ist, mögliche Offenlegung von `SAM`, `SYSTEM`, DPAPI-Material und `MachineKeys` prüfen; diesen Zugriff nicht allein aus **SeManageVolumePrivilege** ableiten.<sup>[[5]](#references)</sup>
- [ ] [**Cloud-Anmeldedaten**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee-SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)-Datei?
- [ ] [**Zwischengespeichertes GPP-Passwort**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Passwort in der [**IIS-Webkonfigurationsdatei**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante Informationen in [**Web-** **Protokollen**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Möchtest du den Benutzer [**nach Anmeldedaten fragen**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interessante [**Dateien im Papierkorb**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Andere [**Registry-Schlüssel mit Anmeldedaten**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Browserdaten**](windows-local-privilege-escalation/index.html#browsers-history) (Datenbanken, Verlauf, Lesezeichen, ...)?
- [ ] [**Allgemeine Passwortsuche**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in Dateien und Registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords), um automatisch nach Passwörtern zu suchen

### [Durchgesickerte Handles](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Hast du Zugriff auf ein Handle eines Prozesses, der von einem Administrator ausgeführt wird?

### [Impersonation von Named-Pipe-Clients](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Prüfen, ob du dies ausnutzen kannst



## References

- [1] [Project Zero - Umgehung des Administrator-Schutzes durch Missbrauch von UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Berechtigungen](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Ändern von Berechtigungen in einem Token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile für physische Datenträger und Volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Verwalten von Berechtigungen in einem Dateisystem](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
