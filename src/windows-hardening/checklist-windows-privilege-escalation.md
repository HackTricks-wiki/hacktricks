# Kontrolelys - Plaaslike Windows-regte-eskalasie

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om plaaslike Windows-regte-eskalasievektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/index.html#system-info)

- [ ] Kry [**stelselinligting**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek vir **kernel**- [**exploits met behulp van scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Gebruik **Google om te soek** vir kernel-**exploits**
- [ ] Gebruik **searchsploit om te soek** vir kernel-**exploits**
- [ ] Interessante inligting in [**omgewingsveranderlikes**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell-geskiedenis**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Interessante inligting in [**internetinstellings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Skywe**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS-exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Outo-opdaterings van derdeparty-agente / IPC-misbruik**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Log-/AV-enumerasie](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Gaan die [**Oudit-** ](windows-local-privilege-escalation/index.html#audit-settings)en [**WEF-** ](windows-local-privilege-escalation/index.html#wef)instellings na
- [ ] Gaan [**LAPS**](windows-local-privilege-escalation/index.html#laps) na
- [ ] Kyk of [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktief is
- [ ] [**LSA-beskerming**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Gekasde credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kyk of daar enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) is
- [ ] [**AppLocker-beleid**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / stilletjie UIAccess-verhoging**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Registerpropagering van Secure Desktop-toeganklikheid (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Gebruikersregte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Gaan die [**huidige** gebruiker se **regte**](windows-local-privilege-escalation/index.html#users-and-groups) na
- [ ] Is jy [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kyk of enige [van hierdie tokens geaktiveer is](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Kyk of jy [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) het om rou volumes te lees en lêer-ACL's te omseil
- [ ] [**Gebruikersessies**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Gaan [**gebruikers se tuisvouers**](windows-local-privilege-escalation/index.html#home-folders) na (toegang?)
- [ ] Gaan die [**wagwoordbeleid**](windows-local-privilege-escalation/index.html#password-policy) na
- [ ] Wat is[ **in die knipbord**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Gaan die **huidige** [**netwerkinligting**](windows-local-privilege-escalation/index.html#network) na
- [ ] Gaan na **verborge plaaslike dienste** wat toegang van buite beperk

### [Prosesse wat loop](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Lêer- en vouertoestemmings**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) van prosesbinaries
- [ ] [**Wagwoordontginning uit geheue**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Onveilige GUI-toepassings**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel credentials met **interessante prosesse** via `ProcDump.exe`? (firefox, chrome, ens ...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kan jy enige **diens wysig**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kan jy die **binary** wysig wat deur enige **diens** **uitgevoer** word?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kan jy die **register** van enige **diens** wysig?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kan jy enige **ongekwoteerde diensbinary-pad** uitbuit?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumereer en aktiveer bevoorregte dienste](windows-local-privilege-escalation/service-triggers.md)

### [**Toepassings**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Skryf** [**toestemmings op geïnstalleerde toepassings**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Opstarttoepassings**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Kwesbare** [**drywers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL-kaping](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **na enige vouer binne PATH skryf**?
- [ ] Is daar enige bekende diensbinary wat **probeer om 'n niebestaande DLL te laai**?
- [ ] Kan jy **na enige binary-vouer skryf**?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk (shares, koppelvlakke, roetes, bure, ...)
- [ ] Let veral op netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows-credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)-credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)-credentials wat jy kan gebruik?
- [ ] Interessante [**DPAPI-credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde van gestoorde [**Wi-Fi-netwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Interessante inligting in [**gestoorde RDP-verbindings**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**onlangs uitgevoerde opdragte**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Wagwoorde in [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**Bestaan AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL-side-loading?

### [Lêers en register (credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credentials**](windows-local-privilege-escalation/index.html#putty-creds) **en** [**SSH-gasheersleutels**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-sleutels in die register**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**onbewaakte lêers**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM- en SYSTEM-rugsteun**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] As [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) teenwoordig is, probeer om rou volumes te lees vir `SAM`, `SYSTEM`, DPAPI-materiaal en `MachineKeys`
- [ ] [**Wolkcredentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)-lêer?
- [ ] [**Gekasde GPP-wagwoord**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS-webkonfigurasielêer**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Interessante inligting in [**web**-**logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy die gebruiker [**vir credentials vra**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Interessante [**lêers in die asblik**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**registerinskrywings wat credentials bevat**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**blaaierdata**](windows-local-privilege-escalation/index.html#browsers-history) (databasisse, geskiedenis, boekmerke, ...)?
- [ ] [**Algemene wagwoordsoektog**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in lêers en die register
- [ ] [**Gereedskap**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties na wagwoorde te soek

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige handler van 'n proses wat deur 'n administrateur uitgevoer word?

### [Named-pipe-kliëntnabootsing](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kyk of jy dit kan misbruik

## References

- [1] [Project Zero - Om Administrator Protection te omseil deur UI Access te misbruik](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
