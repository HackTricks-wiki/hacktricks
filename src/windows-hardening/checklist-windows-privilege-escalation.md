# Lista kontrolna - Lokalna eskalacja uprawnień w systemie Windows

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**Informacje o systemie**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Szukaj **eksploatacji jądra** [**za pomocą skryptów**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Użyj **Google do wyszukiwania** eksploatacji **jądra**
- [ ] Użyj **searchsploit do wyszukiwania** eksploatacji **jądra**
- [ ] Ciekawe informacje w [**zmiennych środowiskowych**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Hasła w [**historii PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Ciekawe informacje w [**ustawieniach Internetu**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Dyski**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Eksploatacja WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logowanie/wyliczanie AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź ustawienia [**Audytu**](windows-local-privilege-escalation/index.html#audit-settings) i [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź, czy [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) jest aktywny
- [ ] [**Ochrona LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź, czy jakikolwiek [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Polityka AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Uprawnienia użytkowników**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**aktualne** uprawnienia **użytkownika**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy jesteś [**członkiem jakiejkolwiek grupy z uprawnieniami**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź, czy masz [jakiekolwiek z tych tokenów włączonych](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź [**domy użytkowników**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**Politykę haseł**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co jest [**w schowku**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź **aktualne** [**informacje o sieci**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź **ukryte lokalne usługi** ograniczone do zewnątrz

### [Uruchamiane procesy](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Uprawnienia [**plików i folderów binariów procesów**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Wydobywanie haseł z pamięci**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Niebezpieczne aplikacje GUI**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Kradnij dane uwierzytelniające z **interesujących procesów** za pomocą `ProcDump.exe` ? (firefox, chrome, itd...)

### [Usługi](windows-local-privilege-escalation/index.html#services)

- [ ] [Czy możesz **zmodyfikować jakąkolwiek usługę**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Czy możesz **zmodyfikować** **binarne** pliki, które są **wykonywane** przez jakąkolwiek **usługę**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Czy możesz **zmodyfikować** **rejestr** jakiejkolwiek **usługi**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Czy możesz skorzystać z jakiejkolwiek **niecytowanej ścieżki binarnej usługi**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Aplikacje**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Uprawnienia do zapisu** [**na zainstalowanych aplikacjach**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacje uruchamiane przy starcie**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Sterowniki**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **zapisać w jakimkolwiek folderze w PATH**?
- [ ] Czy istnieje jakikolwiek znany plik binarny usługi, który **próbuje załadować jakąkolwiek nieistniejącą DLL**?
- [ ] Czy możesz **zapisać** w jakimkolwiek **folderze binarnym**?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Wylicz sieć (udostępnienia, interfejsy, trasy, sąsiedzi, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Dane uwierzytelniające systemu Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) dane uwierzytelniające
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) dane uwierzytelniające, które możesz wykorzystać?
- [ ] Ciekawe [**dane uwierzytelniające DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła zapisanych [**sieci Wifi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Ciekawe informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**niedawno uruchomionych poleceniach**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Menadżer poświadczeń pulpitu zdalnego**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) hasła?
- [ ] [**AppCmd.exe** istnieje](windows-local-privilege-escalation/index.html#appcmd-exe)? Dane uwierzytelniające?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? Ładowanie DLL z boku?

### [Pliki i rejestr (Dane uwierzytelniające)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Dane**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**klucze hosta SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Klucze SSH w rejestrze**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**plikach bezobsługowych**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Jakiekolwiek [**kopie zapasowe SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Dane uwierzytelniające w chmurze**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**Plik McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**plikach konfiguracyjnych IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ciekawe informacje w [**logach**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Czy chcesz [**poprosić użytkownika o dane uwierzytelniające**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Ciekawe [**pliki w Koszu**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inne [**rejestry zawierające dane uwierzytelniające**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Wewnątrz [**danych przeglądarki**](windows-local-privilege-escalation/index.html#browsers-history) (bazy danych, historia, zakładki, ...)?
- [ ] [**Ogólne wyszukiwanie haseł**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i rejestrze
- [ ] [**Narzędzia**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Wyciekające handlerzy](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do jakiegokolwiek handlera procesu uruchomionego przez administratora?

### [Impersonacja klienta Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź, czy możesz to wykorzystać

{{#include ../banners/hacktricks-training.md}}
