# Kontrolelys - Plaaslike Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om na Windows plaaslike privilege escalatie vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/#system-info)

- [ ] Verkry [**Stelselinligting**](windows-local-privilege-escalation/#system-info)
- [ ] Soek na **kernel** [**exploits met behulp van skripte**](windows-local-privilege-escalation/#version-exploits)
- [ ] Gebruik **Google om te soek** na kernel **exploits**
- [ ] Gebruik **searchsploit om te soek** na kernel **exploits**
- [ ] Interessante inligting in [**omgewing veranderlikes**](windows-local-privilege-escalation/#environment)?
- [ ] Wagwoorde in [**PowerShell geskiedenis**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Interessante inligting in [**Internet instellings**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Skyfies**](windows-local-privilege-escalation/#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logging/AV enumerasie](windows-local-privilege-escalation/#enumeration)

- [ ] Kontroleer [**Auditing**](windows-local-privilege-escalation/#audit-settings) en [**WEF**](windows-local-privilege-escalation/#wef) instellings
- [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Kontroleer of [**WDigest**](windows-local-privilege-escalation/#wdigest) aktief is
- [ ] [**LSA Beskerming**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Gekapte Kredensiale**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Kontroleer of enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Beleid**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Gebruiker Privileges**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Kontroleer [**huidige** gebruiker **privileges**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Is jy [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Kontroleer of jy [enige van hierdie tokens geaktiveer het](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Gebruikers Sessies**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Kontroleer [**gebruikers se tuis**](windows-local-privilege-escalation/#home-folders) (toegang?)
- [ ] Kontroleer [**Wagwoord Beleid**](windows-local-privilege-escalation/#password-policy)
- [ ] Wat is [**binne die Klembord**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/#network)

- [ ] Kontroleer **huidige** [**netwerk** **inligting**](windows-local-privilege-escalation/#network)
- [ ] Kontroleer **verborgene plaaslike dienste** wat beperk is tot die buitekant

### [Hardloop Prosesse](windows-local-privilege-escalation/#running-processes)

- [ ] Prosesse binaries [**lêer en vouer toestemmings**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Geheue Wagwoord mynbou**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Onveilige GUI apps**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Steel kredensiale met **interessante prosesse** via `ProcDump.exe` ? (firefox, chrome, ens ...)

### [Dienste](windows-local-privilege-escalation/#services)

- [ ] [Kan jy **enige diens** **wysig**?](windows-local-privilege-escalation/#permissions)
- [ ] [Kan jy die **binaire** wat deur enige **diens** **uitgevoer** word **wysig**?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Kan jy die **register** van enige **diens** **wysig**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Kan jy voordeel trek uit enige **ongekwote diens** binaire **pad**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Toepassings**](windows-local-privilege-escalation/#applications)

- [ ] **Skryf** [**toestemmings op geïnstalleerde toepassings**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Opstart Toepassings**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Kwetsbare** [**Stuurprogramme**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Kan jy **skryf in enige vouer binne PATH**?
- [ ] Is daar enige bekende diens binaire wat **probeer om enige nie-bestaande DLL** te laai?
- [ ] Kan jy **skryf** in enige **binaries vouer**?

### [Netwerk](windows-local-privilege-escalation/#network)

- [ ] Enumereer die netwerk (deel, interfaces, roetes, bure, ...)
- [ ] Neem 'n spesiale kyk na netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows Kredensiale](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials) kredensiale
- [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kredensiale wat jy kan gebruik?
- [ ] Interessante [**DPAPI kredensiale**](windows-local-privilege-escalation/#dpapi)?
- [ ] Wagwoorde van gestoor [**Wifi netwerke**](windows-local-privilege-escalation/#wifi)?
- [ ] Interessante inligting in [**gestoor RDP Verbindinge**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Wagwoorde in [**onlangs uitgevoerde opdragte**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] [**Afgeleë Desktop Kredensiale Bestuurder**](windows-local-privilege-escalation/#remote-desktop-credential-manager) wagwoorde?
- [ ] [**AppCmd.exe** bestaan](windows-local-privilege-escalation/#appcmd-exe)? Kredensiale?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Syde Laai?

### [Lêers en Register (Kredensiale)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Kredensiale**](windows-local-privilege-escalation/#putty-creds) **en** [**SSH gas sleutels**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**SSH sleutels in register**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**onbewaakte lêers**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) rugsteun?
- [ ] [**Cloud kredensiale**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) lêer?
- [ ] [**Gekapte GPP Wagwoord**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS Web konfigurasie lêer**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Interessante inligting in [**web** **logs**](windows-local-privilege-escalation/#logs)?
- [ ] Wil jy [**kredensiale vra**](windows-local-privilege-escalation/#ask-for-credentials) aan die gebruiker?
- [ ] Interessante [**lêers binne die Herwinde Mandjie**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Ander [**register wat kredensiale bevat**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Binne [**Bladsy data**](windows-local-privilege-escalation/#browsers-history) (dbs, geskiedenis, boekmerke, ...)?
- [ ] [**Generiese wagwoord soektog**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in lêers en register
- [ ] [**Hulpmiddels**](windows-local-privilege-escalation/#tools-that-search-for-passwords) om outomaties vir wagwoorde te soek

### [Gelekte Hanteerders](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Het jy toegang tot enige hanteerder van 'n proses wat deur die administrateur uitgevoer word?

### [Pyp Kliënt Imersonasie](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Kontroleer of jy dit kan misbruik

{{#include ../banners/hacktricks-training.md}}
