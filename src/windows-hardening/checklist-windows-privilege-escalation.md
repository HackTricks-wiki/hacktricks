# Lista kontrolna - lokalna eskalacja uprawnień w Windows

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień na Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Przeszukaj w poszukiwaniu **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Użyj **Google** do wyszukania kernel **exploits**
- [ ] Użyj **searchsploit** do wyszukania kernel **exploits**
- [ ] Interesujące informacje w [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Hasła w [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interesujące informacje w [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logowanie/inkrementacja AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź ustawienia [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) i [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź, czy [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) jest aktywny
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź, czy jest jakiś [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**aktualne** uprawnienia użytkownika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy jesteś [**członkiem jakiejś uprzywilejowanej grupy**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź, czy masz włączone któryś z tych tokenów (SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege) [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation)?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź [**katalogi domowe użytkowników**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co jest [**w schowku (Clipboard)**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź **aktualne** [**informacje sieciowe**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź ukryte lokalne usługi ograniczone do zewnątrz

### [Uruchomione procesy](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Uprawnienia do plików i folderów binarek procesów [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Wykradnij poświadczenia z **interesujących procesów** używając `ProcDump.exe` ? (firefox, chrome, itd...)

### [Usługi](windows-local-privilege-escalation/index.html#services)

- [ ] [Czy możesz **zmodyfikować jakąkolwiek usługę**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Czy możesz **zmodyfikować** **binarkę** uruchamianą przez którąkolwiek **usługę**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Czy możesz **zmodyfikować** **rejestr** którejkolwiek **usługi**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Czy możesz wykorzystać niektóry **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [Aplikacje](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **zapisać** w dowolnym folderze w PATH?
- [ ] Czy istnieje znana binarka usługi, która **próbuje załadować nieistniejącą DLL**?
- [ ] Czy możesz **zapisać** w którymś z **folderów z binarkami**?

### [Sieć](windows-local-privilege-escalation/index.html#network)

- [ ] Skanuj sieć (udziały, interfejsy, trasy, sąsiedzi, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Poświadczenia Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) poświadczenia
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) poświadczenia, których możesz użyć?
- [ ] Interesujące [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła zapisanych sieci [**WiFi**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interesujące informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**ostatnio uruchamianych poleceniach**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) hasła?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Poświadczenia?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Pliki i rejestr (poświadczenia)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **oraz** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Jakiekolwiek kopie zapasowe [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) plik?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interesujące informacje w [**logach web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Chcesz [**poprosić użytkownika o poświadczenia**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interesujące [**pliki w Koszu (Recycle Bin)**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inne [**klucze rejestru zawierające poświadczenia**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Wewnątrz [**danych przeglądarki**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historia, zakładki, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i rejestrze
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do jakiegokolwiek handle'a procesu uruchomionego przez administratora?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź, czy możesz to nadużyć

{{#include ../banners/hacktricks-training.md}}
