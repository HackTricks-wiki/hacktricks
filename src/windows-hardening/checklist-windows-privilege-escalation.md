# Kontrolna lista - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora za Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pribavite [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Pretražite [**kernel exploite pomoću scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristite **Google za pretragu** kernel **exploita**
- [ ] Koristite **searchsploit za pretragu** kernel **exploita**
- [ ] Zanimljive informacije u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Passwordi u [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proverite postavke za [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proverite **privilegije** [**trenutnog** korisnika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proverite da li imate [neki od ovih tokena omogućenih](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Proverite da li imate [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) za čitanje raw volume-a i zaobilaženje file ACL-ova
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proverite[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proverite [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta se nalazi[ **unutar Clipboard-a**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Proverite **trenutne** [**network** **informacije**](windows-local-privilege-escalation/index.html#network)
- [ ] Proverite **hidden local services** ograničene za spoljašnji pristup

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) za binaries procesa
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradite credentials pomoću **zanimljivih procesa** preko `ProcDump.exe` ? (firefox, chrome, itd. ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Da li možete **izmeniti neki service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Da li možete **izmeniti** **binary** koji izvršava neki **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Da li možete **izmeniti** **registry** nekog **service-a**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Da li možete iskoristiti **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Da li možete **pisati u bilo koji folder unutar PATH-a**?
- [ ] Da li postoji poznati service binary koji **pokušava da učita neki nepostojeći DLL**?
- [ ] Da li možete **pisati** u bilo koji **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerišite network (shares, interfaces, routes, neighbours, ...)
- [ ] Posebno obratite pažnju na network services koji osluškuju na localhost-u (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] Credentials iz [**Windows Vault-a**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) koje biste mogli da iskoristite?
- [ ] Zanimljivi [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Passwordi sa sačuvanih [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Passwordi u [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwordi u [**Remote Desktop Credentials Manager-u**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Da li postoji [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Passwordi u [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Neki [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] Ako je prisutan [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), pokušajte sa raw-volume čitanjem `SAM`, `SYSTEM`, DPAPI materijala i `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Password u [**IIS Web config file-u**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Želite li da [**zatražite credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Zanimljivi [**files unutar Recycle Bin-a**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Drugi [**registry koji sadrži credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Unutar [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u files i registry-ju
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsku pretragu passworda

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Da li imate pristup handler-u procesa koji je pokrenuo administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proverite da li možete da ga zloupotrebite

## Reference

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
