# Lista kontrolna - lokalne podniesienie uprawnień w Windows

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnego podniesienia uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Wyszukaj **exploitów** na **kernel** [**za pomocą skryptów**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Użyj **Google do wyszukania** **exploitów** na kernel
- [ ] Użyj **searchsploit do wyszukania** **exploitów** na kernel
- [ ] Czy w [**zmiennych środowiskowych**](windows-local-privilege-escalation/index.html#environment) są ciekawe informacje?
- [ ] Czy w [**historii PowerShell**](windows-local-privilege-escalation/index.html#powershell-history) są hasła?
- [ ] Czy w [**ustawieniach internetowych**](windows-local-privilege-escalation/index.html#internet-settings) są ciekawe informacje?
- [ ] [**Dyski**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Agenty innych firm z automatycznymi aktualizacjami / nadużycie IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeracja logów/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź ustawienia [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź, czy [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)jest aktywne
- [ ] [**Ochrona LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Pamięć podręczna poświadczeń**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź, czy jest zainstalowany jakiś [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Zasady AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Ochrona administratora / ciche podniesienie uprawnień UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagacja rejestru ułatwień dostępu w Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Uprawnienia użytkowników**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**uprawnienia** bieżącego użytkownika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy [**należysz do grupy uprzywilejowanej**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź, czy masz włączone [któreś z tych tokenów](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Sprawdź, czy masz [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), aby odczytywać woluminy bezpośrednio i omijać ACL plików
- [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź[ **katalogi domowe użytkowników**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**zasady dotyczące haseł**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co znajduje się[ **w schowku**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź bieżące [**informacje o sieci**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź **ukryte usługi lokalne** niedostępne z zewnątrz

### [Uruchomione procesy](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Uprawnienia do [**plików i folderów**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) plików binarnych procesów
- [ ] [**Wyszukiwanie haseł w pamięci**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Niebezpieczne aplikacje GUI**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Wykradnij poświadczenia z **interesujących procesów** za pomocą `ProcDump.exe`? (firefox, chrome itd. ...)

### [Usługi](windows-local-privilege-escalation/index.html#services)

- [ ] [Czy możesz **zmodyfikować dowolną usługę**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Czy możesz **zmodyfikować** plik **binarny** **uruchamiany** przez dowolną **usługę**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Czy możesz **zmodyfikować** **rejestr** dowolnej **usługi**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Czy możesz wykorzystać **nieujęty w cudzysłowy** **path** pliku binarnego **usługi**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Wyzwalacze usług: enumeracja i uruchamianie uprzywilejowanych usług](windows-local-privilege-escalation/service-triggers.md)

### [**Aplikacje**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Uprawnienia do zapisu** [**w zainstalowanych aplikacjach**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacje uruchamiane podczas startu**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Podatne** [**sterowniki**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **zapisywać w dowolnym folderze ze zmiennej PATH**?
- [ ] Czy istnieje znany plik binarny usługi, który **próbuje załadować nieistniejącą bibliotekę DLL**?
- [ ] Czy możesz **zapisywać** w dowolnym **folderze z plikami binarnymi**?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Przeprowadź enumerację sieci (udziały, interfejsy, trasy, sąsiedzi, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Poświadczenia Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Poświadczenia [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Czy są dostępne poświadczenia [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault), których możesz użyć?
- [ ] Ciekawe [**poświadczenia DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła do zapisanych [**sieci Wi-Fi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Ciekawe informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**ostatnio uruchamianych poleceniach**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Hasła w [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Czy istnieje [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Poświadczenia?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Pliki i rejestr (poświadczenia)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Poświadczenia**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**klucze hostów SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Klucze SSH w rejestrze**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**plikach unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Czy są jakieś kopie zapasowe [**SAM i SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Jeśli dostępne jest [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), spróbuj odczytać bezpośrednio woluminy w poszukiwaniu `SAM`, `SYSTEM`, materiałów DPAPI i `MachineKeys`
- [ ] [**Poświadczenia chmurowe**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Czy istnieje plik [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Zapamiętane hasło GPP**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**pliku konfiguracyjnym IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ciekawe informacje w [**logach** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Czy chcesz [**poprosić użytkownika o poświadczenia**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Ciekawe [**pliki w Koszu**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inne [**miejsca w rejestrze zawierające poświadczenia**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Dane przeglądarki**](windows-local-privilege-escalation/index.html#browsers-history) (bazy danych, historia, zakładki, ...)?
- [ ] [**Ogólne wyszukiwanie haseł**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i rejestrze
- [ ] [**Narzędzia**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do jakiegokolwiek handlera procesu uruchomionego przez administratora?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź, czy możesz to nadużyć

## References

- [1] [Project Zero - Omijanie ochrony administratora przez nadużycie UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
