# Kontrolna lista - Lokalna eskalacija privilegija na Windowsu

{{#include ../banners/hacktricks-training.md}}

### **Najbolji alat za pronalaženje vektora lokalne eskalacije privilegija na Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pribaviti [**informacije o sistemu**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Pretražiti [**exploits kernela pomoću skripti**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Koristiti **Google za pretragu** **exploits kernela**
- [ ] Koristiti **searchsploit za pretragu** **exploits kernela**
- [ ] Zanimljive informacije u [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Lozinke u [**istoriji PowerShell-a**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Zanimljive informacije u [**Internet podešavanjima**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Diskovi**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Automatski update-eri agenata trećih strana / zloupotreba IPC-a**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeracija logging-a/AV-a](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Proveriti podešavanja za [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)i [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Proveriti [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Proveriti da li je [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktivan
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Keširani kredencijali**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Proveriti da li postoji neki [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Proveriti [**privilegije** **trenutnog** korisnika](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Proveriti da li su vam [omogućeni neki od ovih tokena](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Proveriti da li imate [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) za čitanje sirovih volumena i zaobilaženje ACL-ova datoteka
- [ ] [**Sesije korisnika**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Proveriti [ **korisničke početne direktorijume**](windows-local-privilege-escalation/index.html#home-folders) (pristup?)
- [ ] Proveriti [**politiku lozinki**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Šta se nalazi[ **u Clipboard-u**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Proveriti **trenutne** [**mrežne** **informacije**](windows-local-privilege-escalation/index.html#network)
- [ ] Proveriti **skrivene lokalne servise** ograničene za spoljašnji pristup

### [Pokrenuti procesi](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Dozvole nad datotekama i direktorijumima**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) binarnih datoteka procesa
- [ ] [**Iskopavanje lozinki iz memorije**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Nezaštićene GUI aplikacije**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Ukrasti kredencijale pomoću **zanimljivih procesa** putem `ProcDump.exe` ? (firefox, chrome, itd. ...)

### [Servisi](windows-local-privilege-escalation/index.html#services)

- [ ] [Možete li **izmeniti neki servis**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Možete li **izmeniti** **binarni fajl** koji **izvršava** neki **servis**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Možete li **izmeniti** **registry** nekog **servisa**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Možete li iskoristiti **putanju** **binarne datoteke servisa** koja **nije navedena pod navodnicima**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Okidači servisa: enumerisati i aktivirati privilegovane servise](windows-local-privilege-escalation/service-triggers.md)

### [**Aplikacije**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**dozvole nad instaliranim aplikacijama**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplikacije koje se pokreću pri startovanju**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Ranjivi** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Možete li **pisati u bilo koji direktorijum unutar PATH-a**?
- [ ] Da li postoji poznata binarna datoteka servisa koja **pokušava da učita nepostojeći DLL**?
- [ ] Možete li **pisati** u bilo koji **direktorijum sa binarnim datotekama**?

### [Mreža](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerisati mrežu (deljenja, interfejsi, rute, susedi, ...)
- [ ] Posebno obratiti pažnju na mrežne servise koji slušaju na localhost-u (127.0.0.1)

### [Windows kredencijali](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)kredencijali
- [ ] Kredencijali iz [**Windows Vault-a**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) koje biste mogli da koristite?
- [ ] Zanimljivi [**DPAPI kredencijali**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Lozinke sačuvanih [**Wifi mreža**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Zanimljive informacije u [**sačuvanim RDP konekcijama**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Lozinke iz [**Remote Desktop Credential Manager-a**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] Da li [**AppCmd.exe** postoji](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredencijali?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Datoteke i Registry (kredencijali)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**kredencijali**](windows-local-privilege-escalation/index.html#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH ključevi u registry-ju**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Lozinke u [**unattended datotekama**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Bilo kakav [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) backup?
- [ ] Ako je prisutan [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), pokušati čitanje sirovih volumena za `SAM`, `SYSTEM`, DPAPI materijal i `MachineKeys`
- [ ] [**Cloud kredencijali**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Datoteka [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Lozinka u [**IIS Web config datoteci**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Zanimljive informacije u [**web** **logovima**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Želite li da [**zatražite kredencijale**](windows-local-privilege-escalation/index.html#ask-for-credentials) od korisnika?
- [ ] Zanimljive [**datoteke unutar Recycle Bin-a**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Drugi [**registry koji sadrži kredencijale**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Unutar [**podataka Browser-a**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, istorija, bookmarks, ...)?
- [ ] [**Generička pretraga lozinki**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) u datotekama i registry-ju
- [ ] [**Alati**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za automatsku pretragu lozinki

### [Procureli handler-i](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Imate li pristup nekom handler-u procesa koji je pokrenuo administrator?

### [Impersonacija klijenta pipe-a](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Proveriti da li ga možete zloupotrebiti

## References

- [1] [Project Zero - Zaobilaženje zaštite administratora zloupotrebom UI Access-a](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
