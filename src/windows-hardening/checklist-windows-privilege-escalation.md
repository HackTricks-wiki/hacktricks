# Kontrolna lista - Lokalna eskalacija privilegija u Windows-u

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/index.html#system-info)

- [ ] Prikupite [**informacije o sistemu**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Potražite **kernel** [**exploite pomoću skripti**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristite **Google za pretragu** **kernel exploita**
- [ ] Koristite **searchsploit za pretragu** **kernel exploita**
- [ ] Zanimljive informacije u [**env var**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Lozinke u [**istoriji PowerShell-a**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet podešavanjima**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Diskovi**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Automatski ažureri agenata trećih strana / zloupotreba IPC-a**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeracija logovanja/AV-a](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proverite podešavanja [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Proverite [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proverite da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Keširani akreditivi**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proverite da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Zaštita administratora / neprimetno podizanje privilegija pomoću UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagacija registra pristupačnosti Secure Desktop-a (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proverite [**privilegije**](windows-local-privilege-escalation/index.html#users-and-groups) **trenutnog korisnika**
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proverite da li imate [omogućen neki od ovih tokena](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Proverite da li imate [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) za čitanje sirovih volumena i zaobilaženje ACL-ova datoteka
- [ ] [**Korisničke sesije**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proverite [**korisničke matične direktorijume**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proverite [**politiku lozinki**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta se nalazi[ **u Clipboard-u**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Proverite **trenutne** [**mrežne** **informacije**](windows-local-privilege-escalation/index.html#network)
- [ ] Proverite **skrivene lokalne servise** kojima je pristup spolja ograničen

### [Pokrenuti procesi](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Dozvole nad datotekama i direktorijumima**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) binarnih datoteka procesa
- [ ] [**Pronalaženje lozinki u memoriji**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Nebezbedne GUI aplikacije**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukradite akreditive pomoću **zanimljivih procesa** preko `ProcDump.exe`? (firefox, chrome, itd. ...)

### [Servisi](windows-local-privilege-escalation/index.html#services)

- [ ] [Možete li **izmeniti neki servis**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možete li **izmeniti** **binarnu datoteku** koju **izvršava** neki **servis**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možete li **izmeniti** **registar** nekog **servisa**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možete li iskoristiti putanju **necitirane** binarne datoteke nekog **servisa**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Okidači servisa: enumerišite i pokrenite privilegovane servise](windows-local-privilege-escalation/service-triggers.md)

### [**Aplikacije**](windows-local-privilege-escalation/index.html#applications)

- [ ] Dozvole za [**upis u instalirane aplikacije**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacije koje se pokreću pri pokretanju sistema**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ranjivi** [**drajveri**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možete li **pisati u neki direktorijum unutar PATH-a**?
- [ ] Postoji li poznata binarna datoteka servisa koja **pokušava da učita nepostojeći DLL**?
- [ ] Možete li **pisati** u neki **direktorijum sa binarnim datotekama**?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerišite mrežu (deljene resurse, interfejse, rute, susede, ...)
- [ ] Posebno obratite pažnju na mrežne servise koji osluškuju na localhost-u (127.0.0.1)

### [Windows akreditivi](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Akreditivi za [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) akreditivi koje biste mogli da iskoristite?
- [ ] Zanimljivi [**DPAPI akreditivi**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke za sačuvane [**Wi-Fi mreže**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**sačuvanim RDP konekcijama**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Lozinke u [**Remote Desktop Credentials Manager-u**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**Postoji li AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Akreditivi?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Datoteke i registar (akreditivi)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Akreditivi**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH ključevi u registru**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Lozinke u [**unattended datotekama**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Neka [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) rezervna kopija?
- [ ] Ako postoji [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), pokušajte sa čitanjem sirovih volumena da biste pristupili materijalu `SAM`, `SYSTEM`, DPAPI i `MachineKeys`
- [ ] [**Cloud akreditivi**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Datoteka [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config datoteci**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logovima**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Želite li da [**zatražite akreditive**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Zanimljive [**datoteke u Recycle Bin-u**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Drugi [**ključevi registra koji sadrže akreditive**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] [**Podaci pregledača**](windows-local-privilege-escalation/index.html#browsers-history) (baze podataka, istorija, obeleživači, ...)?
- [ ] [**Opšta pretraga lozinki**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u datotekama i registru
- [ ] [**Alati**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsku pretragu lozinki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Imate li pristup handler-u nekog procesa koji je pokrenuo administrator?

### [Impersonation klijenta cevi](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proverite da li možete da ga zloupotrebite

## References

- [1] [Project Zero - Zaobilaženje zaštite administratora zloupotrebom UI Access-a](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
