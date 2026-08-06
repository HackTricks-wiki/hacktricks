# Orodha ya Ukaguzi - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Taarifa za Mfumo](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta [**exploits za kernel kwa kutumia scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google kutafuta** **exploits** za kernel
- [ ] Tumia **searchsploit kutafuta** **exploits** za kernel
- [ ] Kuna taarifa za kuvutia katika [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Kuna passwords katika [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Kuna taarifa za kuvutia katika [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Uchunguzi wa Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kagua mipangilio ya [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)na [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Kagua [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kagua kama [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)imewashwa
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kagua kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kagua [**privileges** za mtumiaji **wa sasa**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**mwanachama wa privileged group yoyote**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kagua kama una [token yoyote kati ya hizi ikiwa imewashwa](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Kagua kama una [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ya kusoma raw volumes na kupita file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kagua [**user homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Kagua [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Kuna nini [**ndani ya Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Kagua [**taarifa** za **network** za **sasa**](windows-local-privilege-escalation/index.html#network)
- [ ] Kagua **hidden local services** zilizozuiwa kufikiwa kutoka nje

### [Processes Zinazoendesha](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**File na folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) za process binaries
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Okoa credentials kwa **interesting processes** kupitia `ProcDump.exe`? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Je, unaweza **kurekebisha service yoyote**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Je, unaweza **kurekebisha** **binary** inayotekelezwa na **service** yoyote?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Je, unaweza **kurekebisha** **registry** ya **service** yoyote?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Je, unaweza kutumia **unquoted service** binary **path** yoyote?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions kwenye installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers** zilizo na **Vulnerabilities**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **kuandika kwenye folder yoyote iliyo ndani ya PATH**?
- [ ] Je, kuna service binary inayojulikana ambayo **inajaribu kupakia DLL yoyote ambayo haipo**?
- [ ] Je, unaweza **kuandika** kwenye **binaries folder** yoyote?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerate network (shares, interfaces, routes, neighbours, ...)
- [ ] Chunguza kwa makini network services zinazosikiliza kwenye localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials za [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credentials za [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) ambazo unaweza kutumia?
- [ ] Kuna [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) za kuvutia?
- [ ] Passwords za [**Wifi networks** zilizohifadhiwa](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Kuna taarifa za kuvutia katika [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Kuna passwords katika [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Kuna passwords za [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe ipo**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **na** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys katika registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Kuna passwords katika [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Kuna backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ikiwa [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) ipo, jaribu raw-volume reads kwa `SAM`, `SYSTEM`, DPAPI material, na `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Kuna file ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Kuna password katika [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Kuna taarifa za kuvutia katika [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Je, unataka [**kuomba credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) kutoka kwa mtumiaji?
- [ ] Kuna [**files ndani ya Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) za kuvutia?
- [ ] Kuna [**registry nyingine iliyo na credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Kuna nini ndani ya [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) katika files na registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta passwords automatically

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, unaweza kufikia handler yoyote ya process inayoendeshwa na administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kagua kama unaweza kuitumia vibaya

## Marejeleo

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
