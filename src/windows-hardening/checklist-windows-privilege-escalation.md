# Checklist - Kuongeza Privilege Ndani ya Windows

{{#include ../banners/hacktricks-training.md}}

### **Zana bora ya kutafuta njia za kuongeza privilege ndani ya Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Maelezo ya Mfumo](windows-local-privilege-escalation/index.html#system-info)

- [ ] Pata [**maelezo ya mfumo**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Tafuta **kernel** [**exploits kwa kutumia scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Tumia **Google kutafuta** **exploits** za kernel
- [ ] Tumia **searchsploit kutafuta** **exploits** za kernel
- [ ] Kuna maelezo ya kuvutia kwenye [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Kuna passwords kwenye [**historia ya PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Kuna maelezo ya kuvutia kwenye [**mipangilio ya Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Visasishi otomatiki vya agent za wahusika wengine / matumizi mabaya ya IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Ukusanyaji wa taarifa za Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Kagua mipangilio ya [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)na [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Kagua [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Kagua kama [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)imewashwa
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credentials zilizohifadhiwa kwenye cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Kagua kama kuna [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Sera ya AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Ulinzi wa Admin / kuinua privilege kimya kwa UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Uenezaji wa registry ya ufikivu kwenye Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privileges za mtumiaji**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Kagua [**privileges** za mtumiaji **wa sasa**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Je, wewe ni [**mwanachama wa kundi lolote lenye privileges**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Kagua kama [privileges hizi zipo kwenye token ya sasa](windows-local-privilege-escalation/access-tokens.md), hata kama zinaonyeshwa kuwa **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Privilege iliyozimwa inaweza kuwashwa tu ikiwa tayari imo kwenye token.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Kagua kama kuna [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), ambayo ni haki ya kufanya matengenezo ya volume. Hii peke yake haithibitishi kuwa unaweza kusoma raw volume; kufungua disk au volume pia kunahitaji ruhusa tofauti.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Vipindi vya watumiaji**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Kagua[ **folda za nyumbani za watumiaji**](windows-local-privilege-escalation/index.html#home-folders) (unaweza kuzifikia?)
- [ ] Kagua [**sera ya password**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Kuna nini[ **ndani ya Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Kagua [**maelezo** ya **mtandao** **wa sasa**](windows-local-privilege-escalation/index.html#network)
- [ ] Kagua **services za ndani zilizofichwa** ambazo hazifikiki kutoka nje

### [Michakato inayoendeshwa](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Ruhusa za [**faili na folda**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) za binaries za michakato
- [ ] [**Uchimbaji wa passwords kutoka kwenye memory**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Programu za GUI zisizo salama**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Unaweza kuiba credentials kwa kutumia **michakato ya kuvutia** kupitia `ProcDump.exe`? (firefox, chrome, n.k.)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Unaweza **kubadilisha service yoyote**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Unaweza **kubadilisha** **binary** inayotekelezwa na **service** yoyote?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Unaweza **kubadilisha** **registry** ya **service** yoyote?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Unaweza kutumia fursa ya **path** ya binary ya **service isiyo na nukuu**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: orodhesha na anzisha services zenye privilege](windows-local-privilege-escalation/service-triggers.md)

### [**Programu**](windows-local-privilege-escalation/index.html#applications)

- [ ] Ruhusa za **kuandika** kwenye [**programu zilizosakinishwa**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Programu zinazoanza wakati wa kuwasha mfumo**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **zilizo hatarini**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Je, unaweza **kuandika kwenye folda yoyote ndani ya PATH**?
- [ ] Je, kuna binary yoyote ya service inayojulikana **kujaribu kupakia DLL isiyopo**?
- [ ] Je, unaweza **kuandika** kwenye **folda yoyote ya binaries**?

### [Mtandao](windows-local-privilege-escalation/index.html#network)

- [ ] Kusanya taarifa za mtandao (shares, interfaces, routes, neighbours, ...)
- [ ] Chunguza kwa makini services za mtandao zinazosikiliza kwenye localhost (127.0.0.1)

### [Credentials za Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credentials za [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Kuna credentials za [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) unazoweza kutumia?
- [ ] Kuna [**credentials za DPAPI**](windows-local-privilege-escalation/index.html#dpapi) za kuvutia?
- [ ] Passwords za [**mitandao ya Wifi**](windows-local-privilege-escalation/index.html#wifi) iliyohifadhiwa?
- [ ] Kuna maelezo ya kuvutia kwenye [**miunganisho ya RDP iliyohifadhiwa**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Kuna passwords kwenye [**amri zilizotekelezwa hivi majuzi**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Passwords za [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe ipo**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Faili na Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credentials**](windows-local-privilege-escalation/index.html#putty-creds) **na** [**funguo za SSH host**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] Kuna [**funguo za SSH kwenye registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Kuna passwords kwenye [**faili za unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Kuna backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Ikiwa ruhusa ya kufikia raw-volume handle inayosomeka imetolewa kivyake, tathmini uwezekano wa kufichuka kwa `SAM`, `SYSTEM`, data ya DPAPI, na `MachineKeys`; usihitimishe kuwa ruhusa hii ipo kwa kutegemea **SeManageVolumePrivilege** pekee.<sup>[[5]](#references)</sup>
- [ ] [**Credentials za cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Kuna faili ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Password ya GPP iliyohifadhiwa kwenye cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Kuna password kwenye [**faili ya IIS Web config**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Kuna maelezo ya kuvutia kwenye [**logs za** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Unataka [**kumwomba mtumiaji credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials)?
- [ ] Kuna [**faili za kuvutia ndani ya Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Kuna [**registry nyingine iliyo na credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Kuna [**data ya Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historia, bookmarks, ...)?
- [ ] [**Tafuta passwords kwa ujumla**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) kwenye faili na registry
- [ ] [**Zana**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) za kutafuta passwords kiotomatiki

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Je, unaweza kufikia handler yoyote ya mchakato unaoendeshwa na administrator?

### [Kuiga Utambulisho wa Mteja wa Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Kagua kama unaweza kuitumia vibaya



## References

- [1] [Project Zero - Kukwepa Ulinzi wa Administrator kwa Kutumia Vibaya UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Kubadilisha Privileges kwenye Token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile kwa disks na volumes halisi](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Kusimamia Privileges kwenye File System](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
