# Orodha ya ukaguzi - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google to search** for kernel **exploits**
- [ ] Tumia **searchsploit to search** for kernel **exploits**
- [ ] Kuna taarifa ya kuvutia katika [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Manenosiri katika [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Taarifa za kuvutia katika [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Angalia [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) na [**WEF** ](windows-local-privilege-escalation/index.html#wef) mipangilio
- [ ] Angalia [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Angalia ikiwa [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) inafanya kazi
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Angalia ikiwa kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Angalia [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Angalia ikiwa una [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Angalia[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (ufikia?)
- [ ] Angalia [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Nini kimepo[ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Angalia **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Angalia **hidden local services** zinazopatikana kutoka nje

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Processes binaries [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Pora credentials kwa **interesting processes** kwa kutumia `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **write in any folder inside PATH**?
- [ ] Je, kuna binary ya huduma inayojulikana ambayo **tries to load any non-existant DLL**?
- [ ] Je, unaweza **write** in any **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Orodhesha mtandao (shares, interfaces, routes, neighbours, ...)
- [ ] Angalia kwa makini network services listening on localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials ambazo unaweza kutumia?
- [ ] Taarifa za kuvutia katika [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Manenosiri za mitandao zilizohifadhiwa za [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Taarifa za kuvutia katika [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Manenosiri katika [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) manenosiri?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Manenosiri katika [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Any [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Nenosiri katika [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Taarifa za kuvutia katika [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Unataka [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) kwa mtumiaji?
- [ ] Taarifa za kuvutia katika [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Mengine [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Ndani ya [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) katika faili na registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) to automatically search for passwords

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, una ufikiaji wa handler yoyote ya mchakato unaoendeshwa na administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Angalia ikiwa unaweza kuitumia vibaya

{{#include ../banners/hacktricks-training.md}}
