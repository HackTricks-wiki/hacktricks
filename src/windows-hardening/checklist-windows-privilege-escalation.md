# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej privilege escalation w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Szukaj [**exploitów** **kernel**](windows-local-privilege-escalation/index.html#version-exploits) używając skryptów
- [ ] Użyj **Google do wyszukiwania** exploitów **kernel**
- [ ] Użyj **searchsploit do wyszukiwania** exploitów **kernel**
- [ ] Interesujące informacje w [**zmiennych środowiskowych**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Hasła w [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interesujące informacje w [**ustawieniach Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Dyski**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Zewnętrzne automatyczne aktualizatory agentów / abuse IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź ustawienia [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź, czy [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)jest aktywny
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź, czy jest jakiś [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**Uprawnienia użytkownika**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**bieżące** uprawnienia **użytkownika**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy jesteś [**członkiem jakiejś uprzywilejowanej grupy**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź, czy masz włączone którykolwiek z tych tokenów [**token manipulation**](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Sprawdź, czy masz [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), aby odczytywać raw volumes i omijać file ACLs
- [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź[ **domy użytkowników**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co jest[ **w Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź **bieżące** [**informacje sieciowe**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź **ukryte lokalne usługi** ograniczone do zewnętrznego dostępu

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Binarne pliki procesów [**uprawnienia do plików i folderów**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Kradnij credentials z **interesujących procesów** przez `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Czy możesz **modyfikować jakąkolwiek usługę**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Czy możesz **modyfikować** **binary**, który jest **uruchamiany** przez jakąkolwiek **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Czy możesz **modyfikować** **registry** jakiejkolwiek **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Czy możesz wykorzystać jakiś **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: wylicz i wyzwól uprzywilejowane usługi](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Zapis** [**uprawnienia do zainstalowanych aplikacji**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) z [**lukami**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **zapisać w jakimkolwiek folderze w PATH**?
- [ ] Czy istnieje jakiś znany binary usługi, który **próbuje załadować nieistniejący DLL**?
- [ ] Czy możesz **zapisać** w jakimkolwiek **folderze binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Wylicz sieć (shares, interfaces, routes, neighbours, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Poświadczenia [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Poświadczenia [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), których mógłbyś użyć?
- [ ] Interesujące [**poświadczenia DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła zapisanych [**sieci Wifi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interesujące informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**ostatnio uruchomionych poleceniach**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Hasła [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Istnieje [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys w registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Jakikolwiek backup [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Jeśli obecny jest [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), spróbuj odczytu raw-volume dla `SAM`, `SYSTEM`, materiału DPAPI i `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Plik [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**pliku IIS Web config**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interesujące informacje w [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Czy chcesz [**poprosić użytkownika o credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interesujące [**pliki w Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inne [**registry zawierające credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Wewnątrz [**dane Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Ogólne wyszukiwanie haseł**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i registry
- [ ] [**Narzędzia**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do jakiegoś handlera procesu uruchomionego przez administratora?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź, czy możesz to nadużyć



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
