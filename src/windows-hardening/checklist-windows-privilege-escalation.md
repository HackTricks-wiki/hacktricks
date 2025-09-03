# Kontrolelys - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om Windows local privilege escalation vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Verkry [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek na **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Gebruik **Google to search** vir kernel **exploits**
- [ ] Gebruik **searchsploit to search** vir kernel **exploits**
- [ ] Interessante inligting in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante inligting in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kontroleer [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) en [**WEF** ](windows-local-privilege-escalation/index.html#wef) instellings
- [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kontroleer of [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) aktief is
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kontroleer of enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kontroleer [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Is jy [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kontroleer of jy enige van hierdie tokens geaktiveer het: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kontroleer [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Kontroleer [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Wat is[ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Kontroleer **huidige** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Kontroleer **hidden local services** wat na die buitekant beperk is

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Kontroleer proses-binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel credentials met **interesting processes** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Skryf** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Kwetsbare** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **write in any folder inside PATH**?
- [ ] Is daar enige bekende service binary wat **tries to load any non-existant DLL**?
- [ ] Kan jy **Skryf** in enige **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk (shares, interfaces, routes, neighbours, ...)
- [ ] Gee besondere aandag aan netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials wat jy kan gebruik?
- [ ] Interessante [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde van gestoorde [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante inligting in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) wagwoorde?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Wagwoorde?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) lêer?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante inligting in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) aan die gebruiker?
- [ ] Interessante [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Binne [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in lêers en register
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties vir wagwoorde te soek

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige handler van 'n proses wat deur administrator uitgevoer word?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kontroleer of jy dit kan misbruik

{{#include ../banners/hacktricks-training.md}}
