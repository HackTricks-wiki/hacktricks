# Lista kontrolna - Lokalne podniesienie uprawnień w Windows

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnego podniesienia uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Wyszukaj [**exploity kernela za pomocą skryptów**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Użyj **Google do wyszukania** **exploitów kernela**
- [ ] Użyj **searchsploit do wyszukania** **exploitów kernela**
- [ ] Interesujące informacje w [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Hasła w [**historii PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interesujące informacje w [**ustawieniach Internetu**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Dyski**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-updatery agentów zewnętrznych / nadużycie IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeracja logowania/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź ustawienia [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź, czy [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)jest aktywny
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź, czy dostępny jest dowolny [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / ciche podniesienie uprawnień UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagacja rejestru ułatwień dostępu Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Uprawnienia użytkownika**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**uprawnienia** bieżącego **użytkownika**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy jesteś [**członkiem dowolnej uprzywilejowanej grupy**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź, czy masz [włączone którekolwiek z tych tokenów](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Sprawdź, czy masz [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), aby odczytywać surowe woluminy i omijać ACL plików
- [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź [ **foldery domowe użytkowników**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co znajduje się[ **w schowku**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź **bieżące** [**informacje o** **sieci**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź **ukryte usługi lokalne** ograniczone dla połączeń z zewnątrz

### [Uruchomione procesy](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Uprawnienia do plików i folderów**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) binariów procesów
- [ ] [**Wydobywanie haseł z pamięci**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Niebezpieczne aplikacje GUI**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradnij poświadczenia za pomocą **interesujących procesów** przez `ProcDump.exe`? (firefox, chrome itd. ...)

### [Usługi](windows-local-privilege-escalation/index.html#services)

- [ ] [Czy możesz **zmodyfikować dowolną usługę**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Czy możesz **zmodyfikować** **plik binarny**, który jest **uruchamiany** przez dowolną **usługę**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Czy możesz **zmodyfikować** **rejestr** dowolnej **usługi**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Czy możesz wykorzystać dowolną **ścieżkę** **binarnego pliku usługi** bez cudzysłowów?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumeracja i uruchamianie uprzywilejowanych usług](windows-local-privilege-escalation/service-triggers.md)

### [**Aplikacje**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Uprawnienia zapisu** [**do zainstalowanych aplikacji**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacje uruchamiane przy starcie**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Podatne** [**sterowniki**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **zapisywać w dowolnym folderze wewnątrz PATH**?
- [ ] Czy istnieje znany binarny plik usługi, który **próbuje załadować nieistniejącą bibliotekę DLL**?
- [ ] Czy możesz **zapisywać** w dowolnym **folderze z binariami**?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Wykonaj enumerację sieci (udziały, interfejsy, trasy, sąsiedzi, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Poświadczenia Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Poświadczenia [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) poświadczenia, których możesz użyć?
- [ ] Interesujące [**poświadczenia DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła zapisanych [**sieci Wi-Fi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interesujące informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**ostatnio uruchamianych poleceniach**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Hasła w [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Czy istnieje [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Poświadczenia?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Pliki i rejestr (poświadczenia)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**poświadczenia**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**klucze hostów SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Klucze SSH w rejestrze**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**plikach unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Czy istnieje kopia zapasowa [**SAM i SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Jeśli obecne jest [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), spróbuj odczytów surowych woluminów dla `SAM`, `SYSTEM`, materiału DPAPI i `MachineKeys`
- [ ] [**Poświadczenia cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Plik [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**pliku konfiguracji IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interesujące informacje w [**logach** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Czy chcesz [**poprosić użytkownika o poświadczenia**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interesujące [**pliki w Koszu**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inny [**rejestr zawierający poświadczenia**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Wewnątrz [**danych przeglądarki**](windows-local-privilege-escalation/index.html#browsers-history) (bazy danych, historia, zakładki, ...)?
- [ ] [**Ogólne wyszukiwanie haseł**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i rejestrze
- [ ] [**Narzędzia**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do dowolnego handlera procesu uruchomionego przez administratora?

### [Podszywanie się pod klienta potoku](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź, czy możesz to wykorzystać

## Referencje

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
