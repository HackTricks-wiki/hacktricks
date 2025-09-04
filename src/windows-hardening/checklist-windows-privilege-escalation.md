# Orodha ya Ukaguzi - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Taarifa za Mfumo](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**Taarifa za Mfumo**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google** kutafuta kernel **exploits**
- [ ] Tumia **searchsploit** kutafuta kernel **exploits**
- [ ] Je, kuna taarifa za kuvutia katika [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Je, kuna nywila katika [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Je, kuna taarifa za kuvutia katika [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Uchunguzi wa Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kagua [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) na [**WEF**](windows-local-privilege-escalation/index.html#wef) mipangilio
- [ ] Kagua [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kagua kama [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) iko imewezeshwa
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kagua kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kagua [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kagua kama una [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kagua [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (ufikaji?)
- [ ] Kagua [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Kuna nini [ **katika Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Kagua [**taarifa za mtandao**](windows-local-privilege-escalation/index.html#network) ya sasa
- [ ] Kagua huduma za ndani zilizofichika zinazotengwa kwa nje

### [Michakato Inayoendeshwa](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Idhini za [**file and folders**] za binaries za michakato (permissions) (windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Pora nywila kwa michakato yenye [**vitu vya kuvutia**] kwa kutumia `ProcDump.exe` ? (firefox, chrome, n.k.)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Je, unaweza **kubadilisha service yoyote**? (windows-local-privilege-escalation/index.html#permissions)
- [ ] Je, unaweza **kubadilisha** **binary** inayotekelezwa na service yoyote? (windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Je, unaweza **kubadilisha** **registry** ya service yoyote? (windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Je, unaweza kuchukua faida ya njia ya binary isiyo na nukuu ya service yoyote? (windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [Programu](windows-local-privilege-escalation/index.html#applications)

- [ ] [**Write**] ruhusa kwenye programu zilizosakinishwa (windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Vulnerable** Drivers](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **kuandika** katika folda yoyote ndani ya PATH?
- [ ] Je, kuna binary ya service inayojulikana ambayo **inajaribu kupakia DLL isiyokuwepo**?
- [ ] Je, unaweza **kuandika** katika **folder za binaries** yoyote?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Fanya uorodheshaji wa mtandao (shares, interfaces, routes, neighbours, ...)
- [ ] Tazama kwa makini huduma za mtandao zinazolisikiliza localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials ambazo unaweza kutumia?
- [ ] Je, kuna [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) za kuvutia?
- [ ] Nywila za [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Taarifa za kuvutia katika [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Nywila katika [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) nywila?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Nywila katika [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Kuna nakala za kuhifadhi za [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Nywila katika [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Taarifa za kuvutia katika [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Unataka [**kuomba nywila**](windows-local-privilege-escalation/index.html#ask-for-credentials) kutoka kwa mtumiaji?
- [ ] Faili za kuvutia ndani ya [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Mengine [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Ndani ya [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) katika files na registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta nywila moja kwa moja

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, una ufikiaji wa handler yoyote ya mchakato unaoendeshwa na administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kagua kama unaweza kuiboresha (abuse) hiyo

{{#include ../banners/hacktricks-training.md}}
