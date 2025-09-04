# Kontrolelys - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows local privilege escalation vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/index.html#system-info)

- [ ] Verkry [**stelselinligting**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek vir **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Gebruik **Google** om na kernel **exploits** te soek
- [ ] Gebruik **searchsploit** om na kernel **exploits** te soek
- [ ] Interessante inligting in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante inligting in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logboek/AV enumerasie](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kontroleer [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)en [**WEF** ](windows-local-privilege-escalation/index.html#wef)instellings
- [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kontroleer of [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)akti ef is
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kontroleer of enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kontroleer [**huidige** gebruiker **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Is jy [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kontroleer of jy enige van hierdie tokens geaktiveer het: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kontroleer [ **tuismappe**](windows-local-privilege-escalation/index.html#home-folders) (toegang?)
- [ ] Kontroleer [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Wat is [ **binne die Knipbord**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Kontroleer **huidige** [**netwerk** **inligting**](windows-local-privilege-escalation/index.html#network)
- [ ] Kyk na verborge plaaslike dienste wat na buite beperk is

### [Aktiewe Prosesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Lêer- en vouerpermissies van proses-binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel kredensiële met **interessante prosesse** via `ProcDump.exe` ? (firefox, chrome, ens ...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kan jy **enige diens wysig**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kan jy die **binêre** wat deur enige **diens** uitgevoer word **wysig**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kan jy die **register** van enige **diens** **wysig**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kan jy voordeel trek uit enige **unquoted service** binêre **pad**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [Toepassings](windows-local-privilege-escalation/index.html#applications)

- [ ] **Skryf** [**permissies op geïnstalleerde toepassings**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Kwetsbare** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **skryf** in enige gids binne **PATH**?
- [ ] Is daar enige bekende diens-binêre wat probeer om enige nie-bestaande **DLL** te laai?
- [ ] Kan jy **skryf** in enige **binêre**-gids?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Ontleed die netwerk (shares, interfaces, routes, neighbours, ...)
- [ ] Neem besondere kennis van netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows-kredensiële](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) kredensiële
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kredensiële wat jy kan gebruik?
- [ ] Interessante [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde van gestoorde [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante inligting in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) wagwoorde?
- [ ] [**AppCmd.exe** bestaan](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredensiële?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Lêers en Register (Kredensiële)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **en** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) rugsteun?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) lêer?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante inligting in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy [**vir kredensiële vra**](windows-local-privilege-escalation/index.html#ask-for-credentials) by die gebruiker?
- [ ] Interessante [**lêers binne die Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**register wat kredensiële bevat**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Binne [**Blaaierdata**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, geskiedenis, boekmerke, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in lêers en register
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties na wagwoorde te soek

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige handler van 'n proses wat deur administrator uitgevoer word?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kyk of jy dit kan misbruik

{{#include ../banners/hacktricks-training.md}}
