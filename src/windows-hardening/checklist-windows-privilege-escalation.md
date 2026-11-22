# Kontrolna lista - Lokalna eskalacija privilegija u Windows-u

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za traženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/index.html#system-info)

- [ ] Prikupite [**informacije o sistemu**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Potražite **kernel** [**exploits pomoću skripti**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristite **Google za pretragu** **kernel exploits**
- [ ] Koristite **searchsploit za pretragu** **kernel exploits**
- [ ] Ima li zanimljivih informacija u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Ima li lozinki u [**istoriji PowerShell-a**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Ima li zanimljivih informacija u [**Internet podešavanjima**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Diskovi**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Automatski ažureri agenata trećih strana / zloupotreba IPC-a**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeracija logovanja/AV-a](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proverite podešavanja za [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Keširani akreditivi**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / tiha eskalacija UIAccess-a**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagacija registra pristupačnosti Secure Desktop-a (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proverite [**privilegije** trenutnog korisnika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proverite da li su [ove privilegije prisutne u trenutnom tokenu](windows-local-privilege-escalation/access-tokens.md), čak i ako su prikazane kao **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Onemogućena privilegija može da se omogući samo ako je već prisutna u tokenu.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Proverite da li postoji [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), odnosno privilegija za održavanje volumena. Ona sama po sebi ne omogućava pristup za čitanje raw volumena; za otvaranje diska ili volumena potrebna su i zasebna prava pristupa.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Korisničke sesije**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proverite [**korisničke početne direktorijume**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proverite [**politiku lozinki**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta se nalazi [**u Clipboard-u**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Proverite **trenutne** [**mrežne** **informacije**](windows-local-privilege-escalation/index.html#network)
- [ ] Proverite da li postoje **skrivene lokalne usluge** nedostupne spolja

### [Pokrenuti procesi](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Dozvole za [**datoteke i direktorijume**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) binarnih datoteka procesa
- [ ] [**Pronalaženje lozinki u memoriji**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Nesigurne GUI aplikacije**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradite akreditive iz **zanimljivih procesa** pomoću `ProcDump.exe` ? (firefox, chrome itd. ...)

### [Usluge](windows-local-privilege-escalation/index.html#services)

- [ ] [Možete li da **izmenite neku uslugu**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možete li da **izmenite** **binarni fajl** koji **pokreće** neka **usluga**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možete li da **izmenite** **registar** neke **usluge**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možete li da iskoristite **putanju binarnog fajla usluge** koja **nije pod navodnicima**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Okidači usluga: enumerišite i pokrenite privilegovane usluge](windows-local-privilege-escalation/service-triggers.md)

### [**Aplikacije**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Dozvole za upis** u [**instalirane aplikacije**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacije koje se pokreću pri startovanju**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ranjivi** [**drajveri**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možete li da **upisujete u neki direktorijum unutar PATH-a**?
- [ ] Postoji li poznati binarni fajl usluge koji **pokušava da učita nepostojeći DLL**?
- [ ] Možete li da **upisujete** u neki **direktorijum sa binarnim fajlovima**?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerišite mrežu (deljenja, interfejse, rute, susede...)
- [ ] Posebno obratite pažnju na mrežne usluge koje osluškuju na localhost-u (127.0.0.1)

### [Windows akreditivi](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Akreditivi za [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Ima li [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) akreditiva koje možete da iskoristite?
- [ ] Ima li zanimljivih [**DPAPI akreditiva**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke za sačuvane [**Wifi mreže**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Ima li zanimljivih informacija u [**sačuvanim RDP vezama**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Lozinke u [**Remote Desktop Credentials Manager-u**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Da li postoji [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Akreditivi?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm) postoji? DLL Side Loading?

### [Datoteke i registar (akreditivi)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**akreditivi**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] Ima li [**SSH ključeva u registru**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Ima li lozinki u [**unattended datotekama**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Ima li rezervne kopije [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ako je pristup za čitanje raw-volume handle-a nezavisno dozvoljen, procenite moguću izloženost `SAM`, `SYSTEM`, DPAPI materijala i `MachineKeys`; nemojte zaključivati da ovaj pristup postoji samo na osnovu **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] [**Cloud akreditivi**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Datoteka [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config datoteci**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Ima li zanimljivih informacija u [**web** **logovima**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Želite li da [**zatražite akreditive**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Ima li zanimljivih [**datoteka u Recycle Bin-u**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Postoje li druge [**stavke registra koje sadrže akreditive**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Ima li nečega u [**podacima pregledača**](windows-local-privilege-escalation/index.html#browsers-history) (baze podataka, istorija, obeleživači...)?
- [ ] [**Opšta pretraga lozinki**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u datotekama i registru
- [ ] [**Alati**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsko traženje lozinki

### [Leaked handleri](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Imate li pristup handler-u nekog procesa koji je pokrenuo administrator?

### [Impersonation klijenta named pipe-a](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proverite da li možete da ga zloupotrebite



## References

- [1] [Project Zero - Zaobilaženje Administrator Protection-a zloupotrebom UI Access-a](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privilegije](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Menjanje privilegija u tokenu](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile za fizičke diskove i volumene](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Upravljanje privilegijama u sistemu datoteka](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
