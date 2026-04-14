# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Zana bora zaidi la kutafuta vectors za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta [**exploits za kernel ukitumia scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google kutafuta** exploits za **kernel**
- [ ] Tumia **searchsploit kutafuta** exploits za **kernel**
- [ ] Kuna info ya kuvutia katika [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwords katika [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Kuna info ya kuvutia katika [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Angalia mipangilio ya [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)na [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Angalia [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Angalia kama [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)iko active
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Angalia kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) yoyote
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Angalia [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Angalia kama una [tokens hizi zozote enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Angalia kama una [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ili kusoma raw volumes na kupita file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Angalia[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Angalia [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Ni nini[ **ndani ya Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Angalia [**network** **information**](windows-local-privilege-escalation/index.html#network) ya **current**
- [ ] Angalia hidden local services zilizozuiliwa kutoka nje

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Binaries za processes: [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Chukua credentials kwa kutumia **interesting processes** kupitia `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] Je, unaweza **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] Je, unaweza **modify** **binary** inayotekelezwa na **service** yoyote?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] Je, unaweza **modify** **registry** ya **service** yoyote?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] Je, unaweza kunufaika na **unquoted service** binary **path** yoyote?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) zenye [**vulnerable**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Unaweza **write** katika folder yoyote ndani ya PATH?
- [ ] Je, kuna service binary inayojulikana ambayo **inajaribu kupakia DLL ambayo haipo**?
- [ ] Unaweza **write** katika folder yoyote ya **binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerate network (shares, interfaces, routes, neighbours, ...)
- [ ] Angalia kwa umakini network services zinazosikiliza kwenye localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials ambazo unaweza kutumia?
- [ ] Kuna [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) za kuvutia?
- [ ] Passwords za [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) zilizohifadhiwa?
- [ ] Kuna info ya kuvutia katika [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwords katika [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwords za [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe) ipo? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **na** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwords katika [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ikiwa [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ipo, jaribu raw-volume reads kwa `SAM`, `SYSTEM`, DPAPI material, na `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Faili ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password katika [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Kuna info ya kuvutia katika [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Je, unataka [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) kutoka kwa user?
- [ ] [**files ndani ya Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) za kuvutia?
- [ ] Nyingine [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Ndani ya [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) katika files na registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta passwords kiotomatiki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, una access kwa handler yoyote ya process inayoendeshwa na administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Angalia kama unaweza kuitumia vibaya



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
