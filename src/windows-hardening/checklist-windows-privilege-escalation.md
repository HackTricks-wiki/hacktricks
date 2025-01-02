# Lista provere - Lokalna eskalacija privilegija na Windows-u

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/#system-info)

- [ ] Pribavite [**informacije o sistemu**](windows-local-privilege-escalation/#system-info)
- [ ] Pretražujte **kernel** [**eksploate koristeći skripte**](windows-local-privilege-escalation/#version-exploits)
- [ ] Koristite **Google za pretragu** kernel **eksploata**
- [ ] Koristite **searchsploit za pretragu** kernel **eksploata**
- [ ] Zanimljive informacije u [**env vars**](windows-local-privilege-escalation/#environment)?
- [ ] Lozinke u [**PowerShell istoriji**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Zanimljive informacije u [**Internet podešavanjima**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Diskovi**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS eksploat**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logovanje/AV enumeracija](windows-local-privilege-escalation/#enumeration)

- [ ] Proverite [**Audit** ](windows-local-privilege-escalation/#audit-settings) i [**WEF** ](windows-local-privilege-escalation/#wef) podešavanja
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/#wdigest) aktivan
- [ ] [**LSA zaštita**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Keširane kredencijale**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker politika**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Proverite [**trenutne** korisničke **privilegije**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Proverite da li imate [neki od ovih tokena aktiviranih](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sesije korisnika**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Proverite [**korisničke foldere**](windows-local-privilege-escalation/#home-folders) (pristup?)
- [ ] Proverite [**Politiku lozinki**](windows-local-privilege-escalation/#password-policy)
- [ ] Šta je [**u Clipboard-u**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/#network)

- [ ] Proverite **trenutne** [**mrežne** **informacije**](windows-local-privilege-escalation/#network)
- [ ] Proverite **sakrivene lokalne usluge** ograničene na spoljašnjost

### [Pokrenuti procesi](windows-local-privilege-escalation/#running-processes)

- [ ] Binarne datoteke procesa [**dozvole za datoteke i foldere**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Rudarenje lozinki iz memorije**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Neosigurane GUI aplikacije**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Ukrao kredencijale sa **zanimljivim procesima** putem `ProcDump.exe` ? (firefox, chrome, itd ...)

### [Usluge](windows-local-privilege-escalation/#services)

- [ ] [Možete li **modifikovati neku uslugu**?](windows-local-privilege-escalation/#permissions)
- [ ] [Možete li **modifikovati** **binarne** datoteke koje **izvodi** neka **usluga**?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Možete li **modifikovati** **registru** neke **usluge**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Možete li iskoristiti neku **necitiranu uslugu** binarnu **putanju**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacije**](windows-local-privilege-escalation/#applications)

- [ ] **Pisanje** [**dozvola na instaliranim aplikacijama**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Aplikacije pri pokretanju**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Ranljive** [**drajvere**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Možete li **pisati u bilo koji folder unutar PATH**?
- [ ] Da li postoji neka poznata binarna datoteka usluge koja **pokušava da učita neku nepostojeću DLL**?
- [ ] Možete li **pisati** u bilo koji **folder binarnih datoteka**?

### [Mreža](windows-local-privilege-escalation/#network)

- [ ] Enumerisati mrežu (deljenja, interfejsi, rute, susedi, ...)
- [ ] Obratite posebnu pažnju na mrežne usluge koje slušaju na localhost (127.0.0.1)

### [Windows kredencijali](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials) kredencijali
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kredencijali koje možete koristiti?
- [ ] Zanimljivi [**DPAPI kredencijali**](windows-local-privilege-escalation/#dpapi)?
- [ ] Lozinke sa sačuvanih [**Wifi mreža**](windows-local-privilege-escalation/#wifi)?
- [ ] Zanimljive informacije u [**sačuvanim RDP vezama**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] [**Menadžer kredencijala za daljinsku radnu površinu**](windows-local-privilege-escalation/#remote-desktop-credential-manager) lozinke?
- [ ] [**AppCmd.exe** postoji](windows-local-privilege-escalation/#appcmd-exe)? Kredencijali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Datoteke i registri (Kredencijali)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Kredencijali**](windows-local-privilege-escalation/#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**SSH ključevi u registru**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Lozinke u [**nepridruženim datotekama**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Da li postoji neki [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) backup?
- [ ] [**Cloud kredencijali**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) datoteka?
- [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config datoteci**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logovima**](windows-local-privilege-escalation/#logs)?
- [ ] Da li želite da [**tražite kredencijale**](windows-local-privilege-escalation/#ask-for-credentials) od korisnika?
- [ ] Zanimljive [**datoteke unutar korpe za otpatke**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Druge [**registri koji sadrže kredencijale**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Unutar [**podataka pretraživača**](windows-local-privilege-escalation/#browsers-history) (dbs, istorija, obeleživači, ...)?
- [ ] [**Generička pretraga lozinki**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) u datotekama i registru
- [ ] [**Alati**](windows-local-privilege-escalation/#tools-that-search-for-passwords) za automatsku pretragu lozinki

### [Procureni handleri](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Da li imate pristup bilo kojem handleru procesa koji pokreće administrator?

### [Impersonacija klijenta cevi](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Proverite da li možete da ga zloupotrebite

{{#include ../banners/hacktricks-training.md}}
