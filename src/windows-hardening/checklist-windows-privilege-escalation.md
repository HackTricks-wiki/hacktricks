# Kontrolelys - Plaaslike Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste tool om na Windows local privilege escalation vectors te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/index.html#system-info)

- [ ] Verkry [**stelselinligting**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek vir **kernel** [**exploits met scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Gebruik **Google om te soek** vir kernel **exploits**
- [ ] Gebruik **searchsploit om te soek** vir kernel **exploits**
- [ ] Interessante inligting in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante inligting in [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kontroleer [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)en [**WEF** ](windows-local-privilege-escalation/index.html#wef)-instellings
- [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kontroleer of [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktief is
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kontroleer of enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) teenwoordig is
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kontroleer die [**current** user se **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Is jy [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kontroleer of jy [enige van hierdie tokens geaktiveer het](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Kontroleer of jy [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) het om raw volumes te lees en file ACLs te omseil
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kontroleer[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (toegang?)
- [ ] Kontroleer [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Wat is[ **binne die Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Kontroleer **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Kontroleer **versteekte plaaslike dienste** wat tot buite-toegang beperk is

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Prosesse se binaries se [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel credentials met **interessante prosesse** via `ProcDump.exe` ? (firefox, chrome, ens ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Kan jy **enige diens wysig**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kan jy die **binary** wat deur enige **diens** **uitgevoer** word, **wysig**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kan jy die **registry** van enige **diens** **wysig**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kan jy voordeel trek uit enige **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumereer en trigger bevoorregte dienste](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **in enige folder binne PATH skryf**?
- [ ] Is daar enige bekende diens-binary wat **probeer om enige nie-bestaande DLL te laai**?
- [ ] Kan jy **in enige binaries-folder skryf**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumereer die network (shares, interfaces, routes, neighbours, ...)
- [ ] Let veral op network-dienste wat op localhost (127.0.0.1) luister

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)-credentials wat jy kan gebruik?
- [ ] Interessante [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde van gestoorde [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante inligting in [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)-wagwoorde?
- [ ] Bestaan [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **en** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)-backup?
- [ ] Indien [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) teenwoordig is, probeer raw-volume-leesaksies vir `SAM`, `SYSTEM`, DPAPI-materiaal en `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)-lêer?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante inligting in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy [**credentials vra**](windows-local-privilege-escalation/index.html#ask-for-credentials) vir die gebruiker?
- [ ] Interessante [**lêers binne die Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**registry wat credentials bevat**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Binne [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in files en registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties vir wagwoorde te soek

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige handler van ’n proses wat deur ’n administrator uitgevoer word?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kontroleer of jy dit kan misbruik

## Verwysings

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
