# Lista kontrolna - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukania Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Uzyskaj [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Szukaj **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Użyj **Google to search** for kernel **exploits**
- [ ] Użyj **searchsploit to search** for kernel **exploits**
- [ ] Interesujące informacje w [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Hasła w [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interesujące informacje w [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Sprawdź [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef) ustawienia
- [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Sprawdź czy [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) jest aktywny
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Sprawdź czy jakikolwiek [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Sprawdź [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Czy jesteś [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Sprawdź czy masz włączone któryś z tych tokenów: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Sprawdź [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (dostęp?)
- [ ] Sprawdź [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Co jest [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Sprawdź **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Sprawdź ukryte lokalne usługi ograniczone na zewnątrz

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Procesy — uprawnienia do plików i folderów binarnych [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Zdobądź poświadczenia z **interesting processes** przy użyciu `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Czy możesz **write in any folder inside PATH**?
- [ ] Czy istnieje jakiś znany binarny serwis, który **tries to load any non-existant DLL**?
- [ ] Czy możesz **write** w którymkolwiek **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Zenumeruj sieć (udostępnienia, interfejsy, trasy, sąsiedzi, ...)
- [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)poświadczenia
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) poświadczenia, których mógłbyś użyć?
- [ ] Interesujące [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Hasła zapisanych [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interesujące informacje w [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Hasła w [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) hasła?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Hasła w [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Jakikolwiek backup [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Hasło w [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interesujące informacje w [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Chcesz [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) od użytkownika?
- [ ] Interesujące [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Inne [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Wewnątrz [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historia, zakładki, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) w plikach i rejestrze
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Czy masz dostęp do jakiegokolwiek handle procesu uruchomionego przez administratora?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Sprawdź czy możesz to wykorzystać

{{#include ../banners/hacktricks-training.md}}
