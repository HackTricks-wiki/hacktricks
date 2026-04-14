# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za traženje Windows lokalnih privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pribavi [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Pretraži **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristi **Google za pretragu** kernel **exploits**
- [ ] Koristi **searchsploit za pretragu** kernel **exploits**
- [ ] Zanimljive informacije u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Lozinke u [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proveri podešavanja [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Proveri [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proveri da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proveri da li postoji bilo koji [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proveri [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li si [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proveri da li imaš aktivirane bilo koje od ovih tokena: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Proveri da li imaš [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) za čitanje raw volumena i zaobilaženje file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proveri [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proveri [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta je[ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Proveri **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Proveri **hidden local services** ograničene na spoljašnji pristup

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Binarni fajlovi procesa [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradi kredencijale iz **interesting processes** preko `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Možeš li da **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možeš li da **modify** **binary** koji izvršava bilo koji **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možeš li da **modify** **registry** bilo kog **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možeš li da iskoristiš bilo koji **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumeriraj i okini privilegovane servise](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možeš li da **write in any folder inside PATH**?
- [ ] Da li postoji neki poznat service binary koji **tries to load any non-existant DLL**?
- [ ] Možeš li da **write** u bilo koji **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumeriraj mrežu (shares, interfaces, routes, neighbours, ...)
- [ ] Obrati posebnu pažnju na mrežne servise koji slušaju na localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)kredencijali
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kredencijali koje možeš da iskoristiš?
- [ ] Zanimljivi [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke sačuvanih [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Lozinke u [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Postoji [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredencijali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Lozinke u [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Bilo koji backup [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ako je prisutan [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), pokušaj raw-volume čitanje za `SAM`, `SYSTEM`, DPAPI materijal i `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Fajl [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Da li želiš da od korisnika [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Zanimljivi [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Drugi [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Unutar [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u fajlovima i registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsko traženje lozinki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Imaš li pristup bilo kom handleru procesa koji je pokrenuo administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proveri da li možeš da ga zloupotrebiš



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
