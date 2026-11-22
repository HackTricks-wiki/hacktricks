# Kontrolelys - Plaaslike Windows-privilege-escalasie

{{#include ../banners/hacktricks-training.md}}

### **Beste hulpmiddel om plaaslike Windows-privilege-escalasie-vektore te soek:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/index.html#system-info)

- [ ] Kry [**stelselinligting**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Soek met [**scripts**](windows-local-privilege-escalation/index.html#version-exploits) vir **kernel**-**exploits**
- [ ] Gebruik **Google om te soek** na kernel-**exploits**
- [ ] Gebruik **searchsploit om te soek** na kernel-**exploits**
- [ ] Enige interessante inligting in [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Wagwoorde in [**PowerShell-geskiedenis**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Enige interessante inligting in [**internetinstellings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Skywe**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS-exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Outomatiese opdateerders van derdeparty-agente / IPC-misbruik**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logboek-/AV-enumerasie](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Gaan die [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)en [**WEF** ](windows-local-privilege-escalation/index.html#wef)-instellings na
- [ ] Gaan [**LAPS**](windows-local-privilege-escalation/index.html#laps) na
- [ ] Kyk of [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)aktief is
- [ ] [**LSA-beskerming**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Gekasde aanmeldbewyse**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kyk of daar enige [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md) is
- [ ] [**AppLocker-beleid**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / stilverhoging met UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Registerpropagering van toeganklikheid op Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Gebruikersregte**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Gaan die [**huidige** gebruiker se **regte**](windows-local-privilege-escalation/index.html#users-and-groups) na
- [ ] Is jy 'n [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kyk of hierdie [regte in die huidige token aanwesig is](windows-local-privilege-escalation/access-tokens.md), selfs al word hulle as **Disabled** getoon: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. 'n Gedeaktiveerde reg kan slegs geaktiveer word as dit reeds in die token is.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Kyk vir [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) as 'n volume-instandhoudingsreg. Dit verleen nie op sy eie leesreg tot rou volumes nie; die oopmaak van 'n skyf of volume het ook afsonderlike toegangsvereistes.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Gebruikersessies**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Gaan [**gebruikers se tuisvouers**](windows-local-privilege-escalation/index.html#home-folders) (toegang?) na
- [ ] Gaan die [**wagwoordbeleid**](windows-local-privilege-escalation/index.html#password-policy) na
- [ ] Wat is [**in die knipbord**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Gaan die **huidige** [**netwerkinligting**](windows-local-privilege-escalation/index.html#network) na
- [ ] Kyk vir **versteekte plaaslike dienste** wat van buite af beperk is

### [Prosesse wat loop](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Lêer- en vouertoestemmings**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) van prosesbinêre lêers
- [ ] [**Wagwoordontginning uit geheue**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Onveilige GUI-toepassings**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Steel aanmeldbewyse met **interessante prosesse** via `ProcDump.exe`? (firefox, chrome, ens. ...)

### [Dienste](windows-local-privilege-escalation/index.html#services)

- [ ] [Kan jy enige **diens wysig**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Kan jy die **binêre lêer** wysig wat deur enige **diens uitgevoer** word?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Kan jy die **register** van enige **diens** wysig?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Kan jy enige **diens se ongekwoteerde binêre lêerpad** uitbuit?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Dienssnellers: enumereer en aktiveer bevoorregte dienste](windows-local-privilege-escalation/service-triggers.md)

### [**Toepassings**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Skryf**-[**toestemmings vir geïnstalleerde toepassings**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Toepassings wat tydens opstart loop**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Kwesbare** [**drywers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Kan jy **na enige vouer binne PATH skryf**?
- [ ] Is daar enige bekende diensbinêre lêer wat **'n niebestaande DLL probeer laai**?
- [ ] Kan jy na enige **binêre-lêergids** skryf?

### [Netwerk](windows-local-privilege-escalation/index.html#network)

- [ ] Enumereer die netwerk (shares, koppelvlakke, roetes, bure, ...)
- [ ] Kyk veral na netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows-aanmeldbewyse](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)-aanmeldbewyse
- [ ] Enige [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault)-aanmeldbewyse wat jy kan gebruik?
- [ ] Enige interessante [**DPAPI-aanmeldbewyse**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Wagwoorde vir gestoorde [**Wifi-netwerke**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Enige interessante inligting in [**gestoorde RDP-verbindings**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Wagwoorde in [**onlangs uitgevoerde opdragte**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Wagwoorde in [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**Bestaan AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Aanmeldbewyse?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Lêers en register (aanmeldbewyse)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Aanmeldbewyse**](windows-local-privilege-escalation/index.html#putty-creds) **en** [**SSH-gasheersleutels**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH-sleutels in die register**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Wagwoorde in [**unattended-lêers**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Enige [**SAM- en SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)-rugsteun?
- [ ] As toegang tot 'n rou-volume-hanteerder onafhanklik toegelaat word, beoordeel moontlike blootstelling van `SAM`, `SYSTEM`, DPAPI-materiaal en `MachineKeys`; moenie hierdie toegang bloot uit **SeManageVolumePrivilege** aflei nie.<sup>[[5]](#references)</sup>
- [ ] [**Wolkaanmeldbewyse**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)-lêer?
- [ ] [**Gekasde GPP-wagwoord**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Wagwoord in [**IIS-webkonfigurasielêer**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Enige interessante inligting in [**web**-**logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Wil jy die gebruiker [**vir aanmeldbewyse vra**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Enige interessante [**lêers in die asblik**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Ander [**registerinskrywings wat aanmeldbewyse bevat**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] In [**blaaierdata**](windows-local-privilege-escalation/index.html#browsers-history) (databasisse, geskiedenis, boekmerke, ...)?
- [ ] [**Algemene wagwoordsoektog**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) in lêers en register
- [ ] [**Gereedskap**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) om outomaties na wagwoorde te soek

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Het jy toegang tot enige hanteerder van 'n proses wat deur 'n administrateur uitgevoer word?

### [Named-pipe-kliëntnabootsing](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kyk of jy dit kan misbruik



## References

- [1] [Project Zero - Om Administrator Protection te omseil deur UI Access te misbruik](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Regte](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Regte in 'n token verander](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile vir fisiese skywe en volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Regte in 'n lêerstelsel bestuur](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
