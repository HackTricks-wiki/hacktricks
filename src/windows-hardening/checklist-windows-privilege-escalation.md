# Kontrolna lista - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje Windows local privilege escalation vektora:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/index.html#system-info)

- [ ] Nabavite [**informacije o sistemu**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Pretražite za **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristite **Google** za pretragu kernel **exploits**
- [ ] Koristite **searchsploit** za pretragu kernel **exploits**
- [ ] Ima li zanimljivih informacija u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Lozinke u [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Evidentiranje/AV enumeracija](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proverite [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) i [**WEF** ](windows-local-privilege-escalation/index.html#wef) podešavanja
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proverite [**trenutne** privilegije korisnika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li ste [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proverite da li imate [bilo koji od ovih tokena omogućen](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proverite [ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proverite [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta je [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Proverite **trenutne** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Proverite **skrivene lokalne servise** ograničene na spolja

### [Pokrenuti procesi](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Dozvole za fajlove i foldere [**Processes binaries file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradite kredencijale iz **interesantnih procesa** pomoću `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Možete li **izmeniti bilo koji servis**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možete li **izmeniti** **binary** koji se **izvršava** za neki **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možete li **izmeniti** **registry** bilo kog **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možete li iskoristiti neki **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Aplikacije**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ranjivi** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možete li **pisati u bilo koji folder unutar PATH**?
- [ ] Postoji li neka poznata servisna binarka koja **pokušava da učita neku nepostojeću DLL**?
- [ ] Možete li **pisati** u bilo koji **folder sa binarnim fajlovima**?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerišite mrežu (shares, interfaces, routes, neighbours, ...)
- [ ] Obratite posebnu pažnju na mrežne servise koji slušaju samo na localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) kredencijali
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kredencijali koje možete iskoristiti?
- [ ] Zanimljivi [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke sa sačuvanih [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) lozinke?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredencijali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Fajlovi i Registry (Kredencijali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Lozinke u [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Postoji li neka [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) fajl?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Želite li da [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Zanimljivi [**fajlovi u Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ostali [**registry koji sadrže kredencijale**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Unutar [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u fajlovima i registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsko pretraživanje lozinki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Imate li pristup nekom handleru procesa koji se izvršava pod administratorom?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proverite da li možete da ga zloupotrebite

{{#include ../banners/hacktricks-training.md}}
