# Kontrolelys - Plaaslike Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows plaaslike privilege escalatie vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/index.html#system-info)

- [ ] Verkry [**Stelselinligting**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek na **kernel** [**exploits met behulp van skripte**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Gebruik **Google om te soek** na kernel **exploits**
- [ ] Gebruik **searchsploit om te soek** na kernel **exploits**
- [ ] Interessante inligting in [**omgewing veranderlikes**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell geskiedenis**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante inligting in [**Internet instellings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Skyfies**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumerasie](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kontroleer [**Auditing**](windows-local-privilege-escalation/index.html#audit-settings) en [**WEF**](windows-local-privilege-escalation/index.html#wef) instellings
- [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kontroleer of [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) aktief is
- [ ] [**LSA Beskerming**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Gekapte Kredensiale**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kontroleer of enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Beleid**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Gebruiker Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kontroleer [**huidige** gebruiker **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Is jy [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kontroleer of jy [enige van hierdie tokens geaktiveer het](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Gebruikers Sessies**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kontroleer [**gebruikers se tuis**](windows-local-privilege-escalation/index.html#home-folders) (toegang?)
- [ ] Kontroleer [**Wagwoord Beleid**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Wat is [**binne die Klembord**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Kontroleer **huidige** [**netwerk** **inligting**](windows-local-privilege-escalation/index.html#network)
- [ ] Kontroleer **verborgene plaaslike dienste** wat beperk is tot die buitekant

### [Huidige Prosesse](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Prosesse binêre [**lêer en vouer toestemmings**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Geheue Wagwoord mynbou**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Onveilige GUI toepassings**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel kredensiale met **interessante prosesse** via `ProcDump.exe` ? (firefox, chrome, ens ...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kan jy **enige diens** **wysig**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kan jy **wysig** die **binêre** wat deur enige **diens** **uitgevoer** word?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kan jy **wysig** die **register** van enige **diens**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kan jy voordeel trek uit enige **ongekwote diens** binêre **pad**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Toepassings**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Skryf** [**toestemmings op geïnstalleerde toepassings**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Opstart Toepassings**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Kwetsbare** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **skryf in enige vouer binne PATH**?
- [ ] Is daar enige bekende diens binêre wat **probeer om enige nie-bestaande DLL** te laai?
- [ ] Kan jy **skryf** in enige **binêre vouer**?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk (deel, interfaces, roetes, bure, ...)
- [ ] Neem 'n spesiale kyk na netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows Kredensiale](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials) kredensiale
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) kredensiale wat jy kan gebruik?
- [ ] Interessante [**DPAPI kredensiale**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde van gestoor [**Wifi netwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante inligting in [**gestoor RDP Verbindinge**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**onlangs uitgevoerde opdragte**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Afgeleë Desktop Kredensiale Bestuurder**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) wagwoorde?
- [ ] [**AppCmd.exe** bestaan](windows-local-privilege-escalation/index.html#appcmd-exe)? Kredensiale?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Syde Laai?

### [Lêers en Register (Kredensiale)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Kredensiale**](windows-local-privilege-escalation/index.html#putty-creds) **en** [**SSH gas sleutels**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH sleutels in register**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**onbewaakte lêers**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups) rugsteun?
- [ ] [**Cloud kredensiale**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) lêer?
- [ ] [**Gekapte GPP Wagwoord**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS Web konfigurasie lêer**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante inligting in [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy [**kredensiale vra**](windows-local-privilege-escalation/index.html#ask-for-credentials) aan die gebruiker?
- [ ] Interessante [**lêers binne die Herwinde Mandjie**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**register wat kredensiale bevat**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Binne [**Bladsy data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, geskiedenis, boekmerke, ...)?
- [ ] [**Generiese wagwoord soektog**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in lêers en register
- [ ] [**Hulpmiddels**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties vir wagwoorde te soek

### [Gelekte Hanteerders](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige hanteerder van 'n proses wat deur die administrateur uitgevoer word?

### [Pyp Kliënt Impersonasie](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kontroleer of jy dit kan misbruik

{{#include ../banners/hacktricks-training.md}}
