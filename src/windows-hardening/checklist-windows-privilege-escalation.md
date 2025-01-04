# Lista - Lokalna eskalacija privilegija na Windows-u

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pribavite [**informacije o sistemu**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Pretražujte **kernel** [**eksploite koristeći skripte**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristite **Google za pretragu** kernel **eksploita**
- [ ] Koristite **searchsploit za pretragu** kernel **eksploita**
- [ ] Zanimljive informacije u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Lozinke u [**PowerShell istoriji**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet podešavanjima**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Diskovi**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS eksploatacija**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logovanje/AV enumeracija](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proverite [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) i [**WEF** ](windows-local-privilege-escalation/index.html#wef) podešavanja
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) aktivan
- [ ] [**LSA zaštita**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Keširane kredencijale**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker politika**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proverite [**trenutne** korisničke **privilegije**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proverite da li imate [neki od ovih tokena aktiviranih](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sesije korisnika**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proverite [**korisničke domove**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proverite [**Politiku lozinki**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta je [**unutar Clipboard-a**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Proverite **trenutne** [**mrežne** **informacije**](windows-local-privilege-escalation/index.html#network)
- [ ] Proverite **sakrivene lokalne usluge** ograničene na spoljašnjost

### [Pokrenuti procesi](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Binarne datoteke procesa [**dozvole za datoteke i foldere**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Rudarenje lozinki iz memorije**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Neosigurane GUI aplikacije**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukrao kredencijale sa **zanimljivih procesa** putem `ProcDump.exe` ? (firefox, chrome, itd ...)

### [Usluge](windows-local-privilege-escalation/index.html#services)

- [ ] [Možete li **modifikovati neku uslugu**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možete li **modifikovati** **binarne** datoteke koje **izvršava** neka **usluga**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možete li **modifikovati** **registru** bilo koje **usluge**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možete li iskoristiti bilo koju **necitiranu uslugu** binarnu **putanju**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Aplikacije**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Pisanje** [**dozvola na instaliranim aplikacijama**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacije pri pokretanju**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ranljive** [**drajvere**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možete li **pisati u bilo koju fasciklu unutar PATH-a**?
- [ ] Da li postoji neka poznata binarna datoteka usluge koja **pokušava da učita neku nepostojeću DLL**?
- [ ] Možete li **pisati** u bilo koju **fasciklu binarnih datoteka**?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerišite mrežu (deljenja, interfejsi, rute, susedi, ...)
- [ ] Obratite posebnu pažnju na mrežne usluge koje slušaju na localhost (127.0.0.1)

### [Windows kredencijali](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) kredencijali
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kredencijali koje možete koristiti?
- [ ] Zanimljive [**DPAPI kredencijale**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke sa sačuvanih [**Wifi mreža**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**sačuvanim RDP vezama**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Menadžer kredencijala za daljinsku radnu površinu**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) lozinke?
- [ ] [**AppCmd.exe** postoji](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredencijali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Datoteke i registri (Kredencijali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Kredencijali**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH ključevi u registru**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Lozinke u [**nepridruženim datotekama**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Da li postoji neki [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] [**Cloud kredencijali**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) datoteka?
- [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config datoteci**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logovima**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Da li želite da [**tražite kredencijale**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Zanimljive [**datoteke unutar Korpe za otpatke**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Druge [**registri koji sadrže kredencijale**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Unutar [**podataka pretraživača**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, istorija, obeleživači, ...)?
- [ ] [**Opšta pretraga lozinki**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u datotekama i registru
- [ ] [**Alati**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsku pretragu lozinki

### [Procureni handleri](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Da li imate pristup bilo kojem handleru procesa koji pokreće administrator?

### [Impersonacija klijenta cevi](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proverite da li možete da to zloupotrebite

{{#include ../banners/hacktricks-training.md}}
